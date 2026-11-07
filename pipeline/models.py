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
    variant: str = 'standard'
    tiered: bool = False


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
    Recipe('calibrated_exploit_rule', 'rule', 'signals'),
    Recipe('lightgbm_sparse_strict', 'lightgbm', variant='sparse'),
    Recipe('lightgbm_sparse_signals', 'lightgbm', 'signals', variant='sparse'),
    Recipe('lightgbm_sparse_identity', 'lightgbm', embedding='identity', variant='sparse'),
    Recipe('tiered_logistic_strict', tiered=True),
    Recipe('tiered_logistic_text', block='text', tiered=True),
    Recipe('tiered_logistic_description', block='text', embedding='description', tiered=True),
    Recipe('tiered_logistic_signals', block='signals', tiered=True),
    Recipe('tiered_logistic_no_history', block='text', no_history=True, tiered=True),
    Recipe('tiered_logistic_entities', block='text', variant='entities_only', tiered=True),
    Recipe('tiered_logistic_no_assigner', block='text', variant='no_assigner', tiered=True),
    Recipe('tiered_lightgbm_strict', 'lightgbm', variant='sparse', tiered=True),
    Recipe('tiered_lightgbm_text', 'lightgbm', 'text', variant='sparse', tiered=True),
    Recipe('tiered_lightgbm_description', 'lightgbm', 'text', 'description', variant='sparse', tiered=True),
]


def select_recipe(recipes, gates, complexity):
    qualified = [r for r in recipes if gates[r.name]['passes_all_four']]
    if not qualified:
        raise ValueError('No recipe passes the four baseline gates')
    best = max(sum(gates[r.name]['margins']) for r in qualified)
    near = [r for r in qualified if sum(gates[r.name]['margins']) >= best - 1]
    return min(near, key=lambda r: (not bool(r.embedding), r.algorithm != 'rule',
                                    r.algorithm == 'lightgbm', complexity[r.name],
                                    bool(r.blend), r.tiered, -sum(gates[r.name]['margins']), r.name)).name


class FittedModel:
    def __init__(self, recipe, seed=2026):
        self.recipe = recipe
        self.seed = seed
        self.pca = None
        self.rule_calibrator = None

    def ranking_score(self, x, probabilities):
        if not self.recipe.tiered:
            return np.asarray(probabilities)
        unique, ordinal = np.unique(probabilities, return_inverse=True)
        # Integer ordinals preserve even adjacent floating-point probabilities.
        return ordinal + x.any_exploit.to_numpy().astype('int64') * len(unique)

    def design(self, x, embedding=None, fit=False):
        x = x.copy()
        if self.recipe.no_history:
            x = x.drop(columns=[c for c in x if 'prior_' in c or 'recent_' in c])
        if self.recipe.variant == 'no_assigner':
            x = x.drop(columns=[c for c in x if c.startswith(('assigner_', 'vendor_'))])
        if self.recipe.variant == 'entities_only':
            x = x.drop(columns=[c for c in x if c.startswith('text_') and 'prior_' not in c and 'recent_' not in c])
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
        if self.recipe.algorithm == 'rule':
            self.columns = ['any_exploit', 'epss_log']
            self.model = LogisticRegression(C=1., max_iter=1000)
            self.model.fit(self.rule_input(x), y)
            assert self.model.coef_[0, 0] > 0, 'Rule calibration must preserve its ranking'
        elif self.recipe.algorithm == 'logistic':
            self.model = LogisticRegression(C=.2, max_iter=2000, solver='lbfgs', random_state=self.seed)
            self.model.fit((design.to_numpy() - self.mean) / self.scale, y)
        else:
            sparse = self.recipe.variant == 'sparse'
            self.model = LGBMClassifier(n_estimators=160, learning_rate=.035, num_leaves=7, max_depth=3,
                                        min_child_samples=40 if sparse else 300,
                                        min_child_weight=.05 if sparse else 2.,
                                        reg_lambda=2. if sparse else 10., reg_alpha=.1 if sparse else .5,
                                        verbosity=-1, n_jobs=6, random_state=self.seed,
                                        deterministic=True, force_col_wise=True)
            self.model.fit(design, y)
        if self.recipe.blend:
            self.rule_calibrator = LogisticRegression(C=1., max_iter=1000)
            self.rule_calibrator.fit(self.rule_input(x), y)
        return self

    def predict(self, x, embedding=None, contributions=False):
        design = self.design(x, embedding)
        if self.recipe.algorithm == 'rule':
            coef = self.model.coef_[0, 0]
            terms = np.column_stack([x.any_exploit.to_numpy() * 8 * coef, x.epss_log.to_numpy() * coef])
            intercept = np.full(len(x), self.model.intercept_[0])
            raw = terms.sum(axis=1) + intercept
        elif self.recipe.algorithm == 'logistic':
            scaled = (design.to_numpy() - self.mean) / self.scale
            terms = scaled * self.model.coef_[0]
            intercept = np.full(len(x), float(self.model.intercept_[0]))
            raw = terms.sum(axis=1) + intercept
        else:
            if contributions:
                parts = self.model.predict(design, pred_contrib=True)
                terms, intercept = parts[:, :-1], parts[:, -1]
                raw = self.model.predict(design, raw_score=True)
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
