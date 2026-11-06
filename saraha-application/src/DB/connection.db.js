
import mongoose from "mongoose";
import { mongoose_url } from "../../config/config.service.js";

export const connectionDB=async()=>{
    try {
        await mongoose.connect(mongoose_url)
        console.log("connection to DB done😍 ");
    } catch (error) {
       console.log("connection to DB failed 😢😢",error)
       ;
    }
}