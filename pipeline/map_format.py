"""Small, explicit typed-array format for canvas and WebGL clients."""
import base64
import numpy as np

FLAG_BITS = {'is_2026': 1, 'in_top500': 2, 'is_past_exploited': 4, 'in_product_watch': 8, 'is_wordpress': 16}


def pack_array(values, dtype):
    array = np.asarray(values, dtype=dtype)
    return {'dtype': array.dtype.str, 'shape': list(array.shape),
            'data': base64.b64encode(array.tobytes(order='C')).decode('ascii')}


def unpack_array(encoded):
    raw = base64.b64decode(encoded['data'], validate=True)
    values = np.frombuffer(raw, dtype=encoded['dtype'])
    assert values.size == int(np.prod(encoded['shape']))
    return values.reshape(encoded['shape'])


def pack_coordinates(points):
    points = np.asarray(points, dtype=np.float64)
    assert points.ndim == 2 and points.shape[1] == 2 and np.isfinite(points).all()
    origin = points.min(axis=0)
    scale = max(float(np.ptp(points, axis=0).max()), 1e-9) / 65535
    quantized = np.rint((points-origin)/scale).astype('<u2')
    return {**pack_array(quantized, '<u2'), 'origin': origin.tolist(), 'scale': scale}


def unpack_coordinates(encoded):
    return unpack_array(encoded).astype(np.float64)*encoded['scale'] + np.asarray(encoded['origin'])


def make_flags(is_2026, in_top500, is_past_exploited, in_product_watch, is_wordpress):
    result = np.zeros(len(is_2026), dtype=np.uint8)
    for values, bit in zip([is_2026, in_top500, is_past_exploited, in_product_watch, is_wordpress], FLAG_BITS.values()):
        result |= np.asarray(values, dtype=np.uint8) * bit
    return result
