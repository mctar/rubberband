import { createTwoFilesPatch } from 'diff';

export function createUnifiedDiff(
  before: string,
  after: string,
  filename: string
): string {
  return createTwoFilesPatch(filename, filename, before, after, '', '', { context: 3 });
}
