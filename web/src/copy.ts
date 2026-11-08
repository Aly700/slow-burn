/** Display copy is separate from the immutable research artifacts. */
export function storyHeading(title?: string) {
  const headings: Record<string, string> = {
    'Two catalog clocks': 'Publication-to-listing delays',
    'Learning to order the public-tool tier': 'Ranking within the public-tool tier',
    'The blind spot has familiar neighbours': 'Description similarity among no-signal CVEs',
  };
  return title ? headings[title] ?? title : '';
}
