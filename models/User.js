import mongoose from "mongoose";


const userSchema = new mongoose.Schema({
    email:{
        type : String,
        unique: true,
        required:true,
    },
    password:{
        type: String,
        required:true,
    },
    verified:{
        type:Boolean,
        default:false,
        required:true,
    },
    otp: {
        type: Number,
    }
});

const User = mongoose.model("people" , userSchema);

export default User;