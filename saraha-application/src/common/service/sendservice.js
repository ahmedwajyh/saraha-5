import {randomInt} from "node:crypto"
import nodemailer from "nodemailer";
import { EMAIL_PASS } from "../../../config/config.service.js";
 const transporter=  nodemailer.createTransport({
service:"gmail",
port:"465",
secure:"true",
auth:{
user:"ahmedwajyh1234@gmail.com",
pass:EMAIL_PASS

}
 });
 export const sendemail= async({
to,
subject,
html="",
attachments=[] }={})=>{
const info= await transporter.sendMail({

from :'"ahmed"<ahmedwajyh1234@gmail.com>',
to,
subject,
html,
attachments

});

console.log(info.messageId);
return info }



export const generate_otp=()=>{

 return randomInt(100000,1000000).toString()
}