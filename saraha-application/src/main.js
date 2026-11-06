import { port } from "../config/config.service.js";
import { connectionDB } from "./DB/connection.db.js";
import { connectionRedis } from "./DB/connection.redis.js";
import { globalErrorHandling } from "./middleware/index.js";
import { userRouter, messageRouter } from "./modules/index.js";
import express from "express";
import cors from "cors";

const app = express();

app.set("case sensitive routing", true);

app.use(cors({
    origin: "*"
}));

app.use(express.json());

await connectionDB();
await connectionRedis();

app.get("/", (req, res) => res.send("welcom to app"));

app.use("/user", userRouter);
app.use("/message", messageRouter);

app.use("{/*dummy}", (req, res) => {
    return res.status(404).json({
        message: "Invalid application routing"
    });
});

app.use(globalErrorHandling);

app.listen(port, () => console.log(`sara7a app listening on port ${port}!👌😘`));
