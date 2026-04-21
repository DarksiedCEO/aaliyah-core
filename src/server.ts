import { createCoreApp } from "./http/createCoreApp";

const port = Number(process.env.PORT ?? 3000);
const app = createCoreApp();

app.listen(port, () => {
  process.stdout.write(`Aaliyah core running on ${port}\n`);
});
