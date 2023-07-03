import express from "express";
import mongoose from "mongoose";
import User from "./models/User.js";
import {config} from "dotenv"
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import cors from "cors"
import nodemailer from "nodemailer"
import jwt from "jsonwebtoken";

const app = express();

config({
    path:"./config.env"
})

app.use(express.json());
app.use(cookieParser());

app.use(cors({
    origin:[process.env.FRONTEND_URL],
    methods:["GET" , "POST" , "PUT" , "DELETE"],
    credentials : true,
}))

mongoose.connect(process.env.MONGO_URL ,{
    dbName:"User_Management_App",
}).then(c=>console.log("Database connected"))
.catch(e=>console.log(e));


app.get("/test", async (req, res) => {
    res.status(200).json({
        success: true,
    })
})


    async function verifyEmail({ email }) {
    try {
        const otpcreated = Math.floor((Math.random() * 10000) + 1000);
        const transporter = nodemailer.createTransport({
            service: "gmail",
            port:587,
            auth: {
                user: process.env.SENDMAILID,
                pass: process.env.SENDMAILPASSWORD,
            }
        });
        const info = await transporter.sendMail({     
             from: `"Hotel Hub" <${process.env.SENDMAILID}>`,   
             to: email, 
             subject: "OTP for registration is", 
             text: `Otp for registration is ${otpcreated}`,  
             html: `<b>OTP for registration is  ${otpcreated}</b>`,
        });
        const { people } = await User.findOne({ email });
        await User.updateOne({email:email} , {$set:{otp:otpcreated}})
        return true;
    } catch (error) {
        return false;
    }
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

app.post("/register" , async (req , res)=>{
    try {
        const { email, Password } = req.body; 
        const people = await User.find({email});
        if(people.length>0){
            return res.status(400).json({
                success:false,
                message:"Already registered user",
            })
        }
        const hashedPassword = await bcrypt.hash(Password , 10);
        await User.create({
            email,
            password:hashedPassword,
        })
        return res.status(200).json({
            success:true,
            message:"Registered Successfully",
        })
    } catch (error) {
        return res.status(500).json({
            success:false,
            message:"Internal Server Error",
        })
    }
})

app.post("/verify", async (req, res) => {
    try {
        const { email } = req.body;
        const people = await User.findOne({ email });
        if (!people) {
        return res.status(404).json({
            success: false,
            message:"Register first",
        })
        }
        if (people.verified) {
        return res.status(400).json({
            success : false,
            message:"Already Verified User",
        })
        }
        if (verifyEmail({ email })) {
            return res.status(200).json({
            success: true,
            message: "Message Sent Successfully",
            });
        } else {
            return res.status(500).json({
            success: false,
            message: "Please try again after some time",
        });
        }
    } catch (error) {
        console.log(error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
})

app.post("/verifyotp", async (req, res) => {
    const { email, OTP } = req.body;
    try {
        const people = await User.findOne({ email });
    if (!people) {
        return res.status(404).json({
            success: false,
            message:"Register first",
        })
    }
    if (people.verified) {
        return res.status(400).json({
            success: false,
            message:"Already Verified User"
        })
        }
        const oneTimePassword = people.otp;
        if (OTP == oneTimePassword) {
        await User.updateOne({ email: email }, { $set: { verified: true } });
        return res.status(200).json({
            success: true,
            message:"Verified Successfully!"
        })
        } else {
        return res.status(404).json({
            success: false,
            message:"Invalid OTP"
        })
    }
    } catch (error) {
        return res.status(400).json({
            success: false,
            message:"Internal Server error! Please try again after some time"
        })
    }
})

app.post("/login", async(req, res) => {
    const { email, Password } = req.body;
    try {
        const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).json({
            success: false,
            message: "Register first",
            verified:true,
        })
        }
        if (!user.verified) {
            return res.status(404).json({
            success: false,
            message: "Verify Your account first",
            verified:false,
        })
        }
    const isMatch = await bcrypt.compare(Password, user.password);
    if (!isMatch) {
        return res.status(404).json({
            success: false,
            message: "Invalid Password",
             verified:true,
        })
    }
        const token = jwt.sign({_id:user._id } , process.env.JWT_SECRET);
        res.status(200).cookie("token" , token , {
        sameSite:"none",
        secure: true
        }).json({
            success:true,
            message: "Login Successful",
            email:email,
            verified:user.verified,
        })
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Internal Server Error",
            verified:true,
        })
    }
})
app.get("/logout", (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(404).json({
            success: false,
            message:"Login First"
        })
    }
    res.status(200).cookie("token" , "" , {
        expires:new Date(Date.now()),
    })
    .json({
        success:true,
    })
})

app.get("/profile", async(req, res) => {
    const { token } = req.cookies;
    try {
        if (!token) {
        return res.status(404).json({
            success: false,
            message:"Login First"
        })
    }    
        const data = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(data._id);
        return res.status(200).json({
            success: true,
            user: user,
        })
    } catch (error) {
        res.status(500).json({
            success: false,
            message:"Internal Server Error"
        }) 
    }
})

app.post("/forgotpassword", async (req, res) => {
    try {
        const { email } = req.body;
        const people = await User.findOne({ email });
        if (!people) {
        return res.status(404).json({
            success: false,
            message:"Register first",
        })
        }
        if (verifyEmail({ email })) {
            return res.status(200).json({
            success: true,
            message: "Message Sent Successfully",
            });
        } else {
            return res.status(500).json({
            success: false,
            message: "Please try again after some time",
        });
        }
    } catch (error) {
        console.log(error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
})

app.post("/verifyforgototp", async (req, res) => {
    const { email, OTP } = req.body;
    try {
        const people = await User.findOne({ email });
    if (!people) {
        return res.status(404).json({
            success: false,
            message:"Register first",
        })
    }
        const oneTimePassword = people.otp;
        if (OTP == oneTimePassword) {
            return res.status(200).json({
                success: true,
               message:"Verified Successfully!"
            })
        } else {
        return res.status(404).json({
            success: false,
            message:"Invalid OTP"
        })
    }
    } catch (error) {
        return res.status(400).json({
            success: false,
            message:"Internal Server error! Please try again after some time"
        })
    }
})

app.post("/changepassword", async (req, res) => {
    const { email, newpassword } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "Register first",
            })
        }
        const hashednewpassword = await bcrypt.hash(newpassword, 10);
        await User.updateOne({ email: email }, { $set: { password: hashednewpassword } });
        return res.status(200).json({
            success: true,
            message: "Password updated",
        });
    } catch (error) {
        return res.status(400).json({
            success: false,
            message:"Internal Server error! Please try again after some time"
        }) 
    }
})

app.listen(3000, () => {
    console.log("Server is working");
});
