import * as child_process from "node:child_process";

declare const router: {
  get(path: string, ...handlers: unknown[]): void;
  post(path: string, ...handlers: unknown[]): void;
};
declare const db: { query(sql: string, values?: unknown[]): void };
declare function requireOwner(...args: unknown[]): void;
const allowedHosts = new Set(["api.example.test"]);

function requireAllowedHost(url: string): string {
  if (!allowedHosts.has(new URL(url).hostname)) throw new Error("host not allowed");
  return url;
}

function executeCommand(command: string) {
  child_process.exec(command);
}

router.get("/search", (req: { query: { name: string } }) => {
  db.query("SELECT * FROM users WHERE name = " + req.query.name);
});

router.get("/search-safe", (req: { query: { name: string } }) => {
  db.query("SELECT * FROM users WHERE name = $1", [req.query.name]);
});

router.post("/commands", (req: { body: { command: string } }) => {
  executeCommand(req.body.command);
  child_process.exec(req.body.command);
});

child_process.exec("echo status");

router.get("/lookup", async (req: { query: { url: string } }) => {
  return fetch(req.query.url);
});

fetch("https://allowed.example.test");

router.get("/proxy", async (req: { query: { url: string } }) => {
  return fetch(requireAllowedHost(req.query.url));
});

function namedLookup(req: { query: { url: string } }) {
  return fetch(req.query.url);
}

router.get("/named-lookup", requireOwner, namedLookup);

router.get("/users/:id", (req: { params: { id: string } }) => {
  return db.query("SELECT * FROM users WHERE id = " + req.params.id);
});

router.get("/users/:id/settings", requireOwner, (req: { params: { id: string } }) => {
  return db.query("SELECT * FROM settings WHERE id = $1", [req.params.id]);
});
