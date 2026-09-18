export function route(name: string): string {
  return `SELECT * FROM users WHERE name = '${name}'`;
}
