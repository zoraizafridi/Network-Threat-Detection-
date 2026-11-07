export function launchReady(src: string, dst: string): boolean {
  return src.length > 0 && dst.length > 0 && src !== dst;
}
