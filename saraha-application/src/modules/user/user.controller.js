import { RoleEnum } from "../../common/enum/user.enum.js";
import { userModel } from "../../DB/model/user.model.js";
import { authentication } from "../../middleware/authentication.middleware.js";
import { authorization } from "../../middleware/authorization.middleware.js";
import {
    login,
    logout,
    profile,
    refreshToken,
    shareProfile,
    signup,
    signupWithGmail,
    updatePassword,
    updateProfile,
    reSendOtp,
    forgetPassword,
    restPassword,
    confirmEmail,
    enableTwoStepVerification,
    confirmTwoStepVerification,
    verifyLoginOtp
} from "./user.service.js";
import { Router } from "express";
import express from "express";
import { Validation } from "../../middleware/validation.middleware.js";
import {
    loginSchema,
    refreshTokenSchema,
    shareProfileSchema,
    signupSchema,
    updatePasswordSchema,
    updateProfileSchema
} from "./user.validation.js";
import { multerLocal } from "../../middleware/multer.middleware.js";
import { messageRouter } from "../message/index.js";

const router = Router({
    strict: true,
    caseSensitive: true,
    mergeParams: true
});

router.use("/:userId/message", messageRouter);

router.post(
    "/signup",
    multerLocal({
        customPath: "admin/ahmed",
        customTypes: ["image/png", "image/jpg", "image.jpg", "image/jpeg"]
    }).fields([
        { name: "attachment", max: 1 },
        { name: "attachments", max: 6 }
    ]),
    Validation(signupSchema),
    signup
);

router.post("/signup/gmail", signupWithGmail);
router.post("/refresh-token", Validation(refreshTokenSchema), refreshToken);
router.post("/login", Validation(loginSchema), login);

router.patch("/resend-otp", reSendOtp);
router.patch("/confirm-email", confirmEmail);
router.patch("/forget-password", forgetPassword);
router.patch("/reset-password", restPassword);

router.patch("/enable-2fa", authentication, enableTwoStepVerification);
router.patch("/confirm-2fa", authentication, confirmTwoStepVerification);

router.get("/profile", authentication, authorization([RoleEnum.USER]), profile);
router.get("/share-profile/:id", Validation(shareProfileSchema), shareProfile);

router.patch("/update-profile", Validation(updateProfileSchema), authentication, updateProfile);
router.patch("/update-password", Validation(updatePasswordSchema), authentication, updatePassword);
router.patch("/logout", authentication, logout);
router.post("/verify-login-otp", verifyLoginOtp);
export default router;