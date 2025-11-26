import app from "../../src/app.ts";
import { handle } from "hono/adapter/netlify/mod.ts";

export default handle(app);

