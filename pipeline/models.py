"""Small, fixed model family and additive log-odds explanations."""
from dataclasses import dataclass

import numpy as np
import pandas as pd
from scipy.special import expit, logit
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression
from lightgbm import LGBMClassifier


@dataclass
class Recipe:
    name: str
    algorithm: str = 'logistic'
    block: str = 'strict'
    embedding: str = ''
    no_history: bool = False
    blend: float = 0.


RECIPES = [
    Recipe('logistic_strict'),
    Recipe('lightgbm_strict', 'lightgbm'),
    Recipe('logistic_signals', block='signals'),
    Recipe('lightgbm_signals', 'lightgbm', 'signals'),
    Recipe('logistic_identity', embedding='identity'),
    Recipe('lightgbm_identity', 'lightgbm', embedding='identity'),
    Recipe('logistic_text', block='text'),
    Recipe('lightgbm_text', 'lightgbm', 'text'),
    Recipe('logistic_description', block='text', embedding='description'),
    Recipe('lightgbm_description', 'lightgbm', 'text', 'description'),
    Recipe('logistic_full_audit', block='full', embedding='description'),
    Recipe('logistic_no_history', block='text', embedding='description', no_history=True),
    Recipe('logistic_strict_blend', blend=.25),
]


class FittedModel:
    def __init__(self, recipe, seed=2026):
        self.recipe = recipe
        self.seed = seed
        self.pca = None
        self.rule_calibrator = None

    def design(self, x, embedding=None, fit=False):
        x = x.copy()
        if self.recipe.no_history:
            x = x.drop(columns=[c for c in x if 'prior_' in c or 'recent_' in c])
        if self.recipe.embedding:
            if embedding is None:
                raise ValueError('Embedding inputs required')
            if fit:
                self.pca = PCA(n_components=24, svd_solver='randomized', random_state=self.seed).fit(embedding)
            values = self.pca.transform(embedding)
            prefix = 'identity_emb_' if self.recipe.embedding == 'identity' else 'description_emb_'
            x = pd.concat([x, pd.DataFrame(values, index=x.index, columns=[f'{prefix}{i:02}' for i in range(values.shape[1])])], axis=1)
        return x

    @staticmethod
    def rule_input(x):
        # Monotonic surrogate of the public-exploit-first rule, calibrated on training only.
        return (x['any_exploit'].to_numpy() * 8 + x.epss_log.to_numpy()).reshape(-1, 1)

    def fit(self, x, y, embedding=None):
        design = self.design(x, embedding, fit=True)
        self.columns = list(design.columns)
        self.mean = design.mean().to_numpy()
        self.scale = np.maximum(design.std(ddof=0).to_numpy(), .1)
        self.train_n = len(y)
        self.train_positives = int(np.sum(y))
        if self.recipe.algorithm == 'logistic':
            self.model = LogisticRegression(C=.2, max_iter=2000, solver='lbfgs', random_state=self.seed)
            self.model.fit((design.to_numpy() - self.mean) / self.scale, y)
        else:
            self.model = LGBMClassifier(n_estimators=160, learning_rate=.035, num_leaves=7, max_depth=3,
                                        min_child_samples=300, min_child_weight=2., reg_lambda=10., reg_alpha=.5,
                                        verbosity=-1, n_jobs=6, random_state=self.seed,
                                        deterministic=True, force_col_wise=True)
            self.model.fit(design, y)
        if self.recipe.blend:
            self.rule_calibrator = LogisticRegression(C=1., max_iter=1000)
            self.rule_calibrator.fit(self.rule_input(x), y)
        return self

    def predict(self, x, embedding=None, contributions=False):
        design = self.design(x, embedding)
        if self.recipe.algorithm == 'logistic':
            scaled = (design.to_numpy() - self.mean) / self.scale
            terms = scaled * self.model.coef_[0]
            intercept = np.full(len(x), float(self.model.intercept_[0]))
            raw = terms.sum(axis=1) + intercept
        else:
            if contributions:
                parts = self.model.predict(design, pred_contrib=True)
                terms, intercept = parts[:, :-1], parts[:, -1]
                raw = parts.sum(axis=1)
            else:
                raw = self.model.predict(design, raw_score=True)
        if self.recipe.blend:
            weight = self.recipe.blend
            rule = self.rule_calibrator.decision_function(self.rule_input(x))
            raw = (1 - weight) * raw + weight * rule
            if contributions:
                terms *= 1 - weight
                intercept = (1 - weight) * intercept + weight * self.rule_calibrator.intercept_[0]
                extra = weight * self.rule_input(x)[:, 0] * self.rule_calibrator.coef_[0, 0]
                terms = np.column_stack([terms, extra])
        probability = expit(raw)
        if contributions:
            names = self.columns + (['exploit_rule_blend'] if self.recipe.blend else [])
            assert np.allclose(terms.sum(axis=1) + intercept, raw, atol=1e-6)
            return probability, terms, intercept, names
        return probability
