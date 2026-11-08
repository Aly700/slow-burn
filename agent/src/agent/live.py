"""One warm model worker shared by HTTP and streamed investigations."""
import asyncio
import json
import threading
import time

from .client import ToolClient
from .model import Granite
from .record import save_record
from .runtime import Runner
from .store import now


def preview(output):
    def shorten(value, depth=0):
        if isinstance(value,str):
            return value if len(value)<=180 else value[:177]+'...'
        if isinstance(value,dict):
            return {k:shorten(v,depth+1) for k,v in list(value.items())[:4]} if depth<2 else '[object]'
        if isinstance(value,list):
            return [shorten(v,depth+1) for v in value[:3]] if depth<2 else f'[{len(value)} values]'
        return value
    preferred=['cve_id','snapshot_month','rank','score','signals','vendor_candidate','vendor','prior_kev','latest_cve','last_added','matches','months','allowed','reason','description']
    keys=list(dict.fromkeys([k for k in preferred if k in output]+list(output)))[:8]
    return {k:shorten(output[k]) for k in keys}


class LiveJob:
    def __init__(self, run, streamed=True, fixture=None):
        self.run_id=run['run_id']
        self.streamed=streamed
        self.fixture=fixture
        self.question=run.get('question')
        self.started=time.monotonic()
        self.cancel_event=threading.Event()
        self.finished=asyncio.Event()
        self.output=asyncio.Queue()
        self.events=[]

    def cancel(self):
        if not self.finished.is_set(): self.cancel_event.set()

    def publish(self, name, data):
        elapsed=round((time.monotonic()-self.started)*1000)
        event={'event':name,'data':{**data,'t_ms':elapsed},'t_ms':elapsed}
        self.events.append(event)
        self.output.put_nowait(event)

    async def emit(self,name,data):
        self.publish(name,data)
        await asyncio.sleep(0)

    async def stream(self):
        try:
            while True:
                event=await self.output.get()
                yield f"event: {event['event']}\ndata: {json.dumps(event['data'],ensure_ascii=False)}\n\n"
                if event['event']=='done': break
        finally:
            self.cancel()


class LiveService:
    def __init__(self,settings,store,model):
        self.settings,self.store,self.model=settings,store,model
        self.queue=asyncio.Queue(maxsize=16)
        self.jobs={}
        self.active=None
        self.loaded_at=None
        self.error=None
        self.client=None

    async def start(self):
        self.ready=asyncio.get_running_loop().create_future()
        self.worker=asyncio.create_task(self.work())
        await self.ready

    async def close(self):
        for job in list(self.jobs.values()): job.cancel()
        if not self.worker.done():
            await self.queue.put(None)
        await asyncio.gather(self.worker,return_exceptions=True)
        if hasattr(self.model, 'close'):
            self.model.close()

    def submit(self,cve_id=None,streamed=True,fixture=None,question=None):
        if self.error: raise RuntimeError('investigation worker unavailable')
        if self.queue.full(): raise asyncio.QueueFull()
        model_name=getattr(self.model,'source_name',self.model.name)
        run=self.store.create_question(question,model_name) if question is not None else self.store.create(cve_id,model_name,list_name='live' if streamed else 'top500')
        job=LiveJob(run,streamed,fixture)
        position=self.queue.qsize()+int(self.active is not None)
        job.publish('start',{'run_id':run['run_id'],**({'question':question} if question is not None else {'cve_id':cve_id}),'model':run['model'],'started_at':run['started_at'],**({'fixture':fixture} if fixture else {})})
        job.publish('state',{'state':'RECEIVED','queued':bool(position),'position':position,'message':'Queued for Granite' if position else 'Ready to investigate'})
        self.jobs[job.run_id]=job
        self.queue.put_nowait(job)
        return job

    async def work(self):
        try:
            await asyncio.to_thread(self.model.warmup)
            async with ToolClient(self.settings, prepare_live=isinstance(self.model,Granite)) as client:
                self.client=client
                self.loaded_at=now()
                self.ready.set_result(True)
                while True:
                    job=await self.queue.get()
                    try:
                        if job is None: return
                        self.active=job
                        queue_ms=round((time.monotonic()-job.started)*1000)
                        from .analyst import AskRunner
                        runner=AskRunner if job.question is not None else Runner
                        result=await runner(self.settings,self.store,self.model).run(job.run_id,client,emit=job.emit,cancel_event=job.cancel_event,fixture=job.fixture)
                        self.store.update(job.run_id,metrics={**result.get('metrics',{}),'queue_ms':queue_ms})
                        result=self.store.get(job.run_id)
                        if self.settings.public:
                            result['public'] = True
                        if job.streamed:
                            folder='ask_runs' if job.question is not None else 'live_runs'
                            save_record(self.settings.cache/folder/f'{job.run_id}.json',result)
                        if job.question is not None and result['state']=='VERIFIED':
                            await job.emit('answer',result['answer'])
                        elif result['state']=='WAITING_APPROVAL':
                            await job.emit('briefing',{'run':result})
                        else:
                            await job.emit('error',{'message':result.get('error',{}).get('message','Investigation failed')})
                    except Exception as exc:
                        message=f'Live delivery failed: {str(exc)[:300]}'
                        try:
                            run=self.store.get(job.run_id)
                            if run['state'] in {'RECEIVED','INVESTIGATING'}:
                                self.store.transition(job.run_id,'FAILED')
                                job.publish('state',{'state':'FAILED'})
                            self.store.update(job.run_id,error={'code':'live_delivery_failed','message':message})
                        except Exception:
                            pass
                        job.publish('error',{'message':message})
                    except BaseException:
                        try:
                            run=self.store.get(job.run_id)
                            if run['state'] in {'RECEIVED','INVESTIGATING'}:
                                self.store.transition(job.run_id,'FAILED')
                                job.publish('state',{'state':'FAILED'})
                            self.store.update(job.run_id,error={'code':'worker_failed','message':'Local investigation worker stopped'})
                        except Exception:
                            pass
                        job.publish('error',{'message':'Local investigation worker stopped'})
                        raise
                    finally:
                        if job is not None:
                            job.publish('done',{'run_id':job.run_id,'duration_ms':round((time.monotonic()-job.started)*1000)})
                            job.finished.set()
                            self.jobs.pop(job.run_id,None)
                        self.active=None
                        self.queue.task_done()
        except BaseException as exc:
            self.error=type(exc).__name__
            if not self.ready.done(): self.ready.set_exception(exc)
            # A failed worker must close pending streams and release queue waiters.
            for pending in list(self.jobs.values()):
                pending.cancel()
                try:
                    run=self.store.get(pending.run_id)
                    if run['state'] in {'RECEIVED','INVESTIGATING'}:
                        self.store.transition(pending.run_id,'FAILED')
                    self.store.update(pending.run_id,error={'code':'worker_failed','message':'Local investigation worker stopped'})
                except Exception:
                    pass
                pending.publish('error',{'message':'Local investigation worker stopped'})
                pending.publish('done',{'run_id':pending.run_id,'duration_ms':round((time.monotonic()-pending.started)*1000)})
                pending.finished.set()
            self.jobs.clear()
            while not self.queue.empty():
                self.queue.get_nowait()
                self.queue.task_done()
            raise
