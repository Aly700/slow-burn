"""Display policy for the complete-cohort capability exports."""
from pipeline.publication import BLOCKED_DIGESTS, display_description as filtered_description

# Additional names occur in the complete cohort but not the frozen display export.
# These rules affect visible text only, never identity matching or embedding inputs.
PUBLIC_DIGESTS = BLOCKED_DIGESTS | {
    '3ea125d0bff386e6754b3782b300016fc79a9cf8f8669c0a5c3db64467ddb681',
    '7d3194f79e645c42e4396dda38be04766810ec6a00d00aced3ffc2a0a1f1a9ef',
    'c70eca6b0f88f44d81a41311647e50fda1ac454ec04ffd442b0eb4743a993131',
}


def display_description(text):
    return filtered_description(text, blocked=PUBLIC_DIGESTS)
