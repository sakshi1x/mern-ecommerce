import {axiosi} from '../../config/axios'
import axios from 'axios';
function getCookie(name) {
    console.log("cookoe",document.cookie)
    let value = `; ${document.cookie}`;
    let parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}
// When your app loads, fetch the CSRF token

  
export const signup=async(cred)=>{
    try {
        // await fetchCsrfToken(); // Fetch the token first
    
        const csrfToken = getCookie("XSRF-TOKEN");
        // const csrfToken = getCookie('XSRF-TOKEN');
        if (csrfToken) {
            return axios.post("https://localhost:8000/auth/signup", cred, {
                headers: { "X-XSRF-TOKEN": csrfToken },
                withCredentials: true // This ensures that cookies are sent with requests
            });
        }
        else{ console.log("no token")}
        
    } catch (error) {
        throw error.response.data
    }
}
export const login=async(cred)=>{
    try {
        const csrfToken = getCookie("XSRF-TOKEN");
        // const csrfToken = getCookie('XSRF-TOKEN');
        if (csrfToken) {
            return axios.post("https://localhost:8000/auth/login", cred, {
                headers: { "X-XSRF-TOKEN": csrfToken },
                withCredentials: true // This ensures that cookies are sent with requests
            });
        }
        else{ console.log("no token")}
       
    } catch (error) {
        throw error.response.data
    }
}
export const verifyOtp=async(cred)=>{
    try {
        const res=await axiosi.post("auth/verify-otp",cred)
        return res.data
    } catch (error) {
        throw error.response.data
    }
}
export const resendOtp=async(cred)=>{
    try {
        const res=await axiosi.post("auth/resend-otp",cred)
        return res.data
    } catch (error) {
        throw error.response.data
    }
}
export const forgotPassword=async(cred)=>{
    try {
        const res=await axiosi.post("auth/forgot-password",cred)
        return res.data
    } catch (error) {
        throw error.response.data
    }
}
export const resetPassword=async(cred)=>{
    try {
        const res=await axiosi.post("auth/reset-password",cred)
        return res.data
    } catch (error) {
        throw error.response.data
    }
}
export const checkAuth=async(cred)=>{
    try {
        const res=await axiosi.get("auth/check-auth")
        return res.data
    } catch (error) {
        throw error.response.data
    }
}
export const logout=async()=>{
    try {
        const res=await axiosi.get("auth/logout")
        return res.data
    } catch (error) {
        throw error.response.data
    }
}