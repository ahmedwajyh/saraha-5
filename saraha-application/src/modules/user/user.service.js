import {
  KEY_ACCESS,
  KEY_REFRESH,
  SALT,
} from "../../../config/config.service.js";

import {
  Decrypt,
  Encrypt
} from "../../common/security/encryption.security.js";

import {
  Compare,
  Hash
} from "../../common/security/hash.security.js";

import {
  create,
  findById,
  findOne,
  findOnedAndUpdate,
} from "../../DB/service/base.repository.js";

import { userModel } from "../../DB/model/user.model.js";

import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";

const client = new OAuth2Client();

import { randomUUID } from "node:crypto";

import {
  deleteKey,
  keys,
  setValue,
  getValue,
  incr,
  ttl
} from "../../DB/service/redis.service.js";

import {
  sendemail,
  generate_otp
} from "../../common/service/sendservice.js";

import { emailTemplate } from "../../common/service/html.template.js";

import { eventEmitter } from "../../common/utils/events.js";


// ================= SEND OTP HELPER =================

const sendOtp = async ({ email, isConfirmed = false }) => {

  const user = await findOne({
    model: userModel,
    filter: {
      email,
      isConfirmed: { $exists: isConfirmed }
    },
  });

  if (!user) {
    throw new Error(
      "user not exist or already confirmed the email",
      { cause: { status: 400 } }
    );
  }

  // Check OTP TTL

  const ttlOtp = await ttl(`otp::${email}`);

  if (ttlOtp > 0) {
    throw new Error(
      `can't resend otp after ${ttlOtp}`,
      { cause: { status: 400 } }
    );
  }

  // Check block TTL

  const blockTtlOtp = await ttl(`otp::bloke::${email}`);

  if (blockTtlOtp > 0) {
    throw new Error(
      `you can resend otp after ${blockTtlOtp}`,
      { cause: { status: 400 } }
    );
  }

  // Check maximum attempts

  let maxOtp = Number(
    await getValue(`otp::max::${email}`) || 0
  );

  if (maxOtp >= 4) {

    await setValue({
      key: `otp::bloke::${email}`,
      value: email,
      ttl: 60 * 7,
    });

    await setValue({
      key: `otp::max::${email}`,
      value: 0,
      ttl: 60 * 10
    });

    throw new Error(
      "you have exceeded the maximum number of tries and you have a block for 7 min",
      { cause: { status: 400 } }
    );

  }

  // Generate OTP

  const otp = await generate_otp();

  await setValue({
    key: `otp::${email}`,
    value: await Hash(otp, SALT),
    ttl: 120,
  });

  // Send Email

  eventEmitter.emit("confirm_email", async () => {

    await sendemail({
      to: email,
      subject: "Welcome to ahmed",
      html: emailTemplate({
        title: "Verify your email",
        subtitle: "Use the code below to finish signing in.",
        otp,
        otpExpiry: "This code expires in 2 minutes.",
      })
    });

  });

  // Increase attempts

  if (maxOtp === 0) {
    await setValue({
      key: `otp::max::${email}`,
      value: 1,
      ttl: 60 * 10
    });
  } else {
    await incr(`otp::max::${email}`);
  }

};


// ================= SIGNUP =================

export const signup = async (req, res, next) => {

  try {

    const {
      fName,
      lName,
      email,
      password,
      phone,
      gender,
      DOB,
      age
    } = req.body;

    const ExistUser = await findOne({
      model: userModel,
      filter: { email: email },
    });

    if (ExistUser) {
      throw new Error("email already exist", {
        cause: { status: 407 }
      });
    }

    const path_cover = [];

    for (const file of req.files.attachments) {
      path_cover.push(file.path);
    }

    const data = await create({
      model: userModel,
      data: {
        fName,
        lName,
        email,
        password: await Hash(password, SALT),
        phone: await Encrypt(phone),
        gender,
        DOB,
        age,
        profileImage: req.files.attachment[0].path,
        coverImage: path_cover,
      },
    });

    // Generate OTP

    const otp = await generate_otp();

    await setValue({
      key: `otp::${email}`,
      value: await Hash(otp, SALT),
      ttl: 120
    });

    await setValue({
      key: `otp::max::${email}`,
      value: 1,
      ttl: 60 * 10
    });

    // Send Email

    eventEmitter.emit("confirm_email", async () => {

      await sendemail({
        to: email,
        subject: "confirm Email",
        html: emailTemplate({
          title: "Verify your email",
          subtitle: "Use the code below to finish signing in.",
          otp,
          otpExpiry: "This code expires in 2 minutes.",
        })
      });

    });

    res.status(200).json({ data });

  } catch (error) {

    res.status(error.cause?.status || 500).json({
      msg: error.message
    });

  }

};


// ================= RESEND OTP =================

export const reSendOtp = async (req, res, next) => {

  try {

    const { email } = req.body;

    await sendOtp({
      email,
      isConfirmed: false
    });

    res.status(200).json({
      message: "OTP sent successfully"
    });

  } catch (error) {

    res.status(error.cause?.status || 500).json({
      msg: error.message
    });

  }

};


// ================= FORGET PASSWORD =================

export const forgetPassword = async (req, res, next) => {

  try {

    const { email } = req.body;

    await sendOtp({
      email,
      isConfirmed: true
    });

    res.status(200).json({
      message: "OTP sent successfully"
    });

  } catch (error) {

    res.status(error.cause?.status || 500).json({
      msg: error.message
    });

  }

};


// ================= RESET PASSWORD =================

export const restPassword = async (req, res, next) => {

  try {

    let {
      email,
      otp,
      password
    } = req.body;

    const otpValue = await getValue(`otp::${email}`);

    if (!otpValue) {
      throw new Error("otp is expire", {
        cause: { status: 400 }
      });
    }

    if (!(await Compare(otp, otpValue))) {
      throw new Error("invalid otp", {
        cause: { status: 400 }
      });
    }

    password = await Hash(password, SALT);

    const user = await findOnedAndUpdate({
      model: userModel,
      filter: {
        email,
        isConfirmed: { $exists: true },
      },
      update: {
        isConfirmed: true,
        password,
      },
    });

    if (!user) {
      throw new Error(
        "user not exist or already confirmed the email",
        { cause: { status: 400 } }
      );
    }

    await deleteKey(`otp::${email}`);

    res.status(200).json({
      message: "password reset successfully",
      data: user
    });

  } catch (error) {

    res.status(error.cause?.status || 500).json({
      msg: error.message
    });

  }

};


// ================= CONFIRM EMAIL =================

export const confirmEmail = async (req, res, next) => {

  try {

    const {
      email,
      otp
    } = req.body;

    const otpValue = await getValue(`otp::${email}`);

    if (!otpValue) {
      throw new Error("otp is expire", {
        cause: { status: 400 }
      });
    }

    if (!(await Compare(otp, otpValue))) {
      throw new Error("invalid otp", {
        cause: { status: 400 }
      });
    }

    const user = await findOnedAndUpdate({
      model: userModel,
      filter: {
        email,
        isConfirmed: { $exists: false },
      },
      update: {
        isConfirmed: true,
      },
    });

    if (!user) {
      throw new Error(
        "user not exist or already confirmed the email",
        { cause: { status: 400 } }
      );
    }

    await deleteKey(`otp::${email}`);

    res.status(200).json({
      message: "email confirmed successfully",
      data: user
    });

  } catch (error) {

    res.status(error.cause?.status || 500).json({
      msg: error.message
    });

  }

};


// ================= SIGNUP WITH GMAIL =================

export const signupWithGmail = async (req, res, next) => {

  try {

    const { idToken } = req.body;

    const ticket = await client.verifyIdToken({
      idToken,
      audience:
        "867768865965-l6sk69spvkgncdj1ni3oc3tphi8nk00b.apps.googleusercontent.com",
    });

    const {
      family_name,
      given_name,
      email,
      email_verified,
      picture
    } = ticket.getPayload();

    let user = await findOne({
      model: userModel,
      filter: { email: email.toLowerCase() },
    });

    if (!user) {

      user = await create({
        model: userModel,
        data: {
          fName: given_name,
          lName: family_name,
          email,
          profileImage: picture,
          isConfirmed: email_verified,
          provider: "google",
        },
      });

    }

    if (user.provider == "system") {
      throw new Error("pls login with system", {
        cause: { status: 400 }
      });
    }

    const access_token = jwt.sign(
      {
        id: user._id,
      },
      KEY_ACCESS,
      {
        expiresIn: 300,
        issuer: "https://localhost:3000",
      },
    );

    const refresh_token = jwt.sign(
      {
        id: user._id,
      },
      KEY_REFRESH,
      {
        expiresIn: 300,
        issuer: "https://localhost:3000",
      },
    );

    res.status(200).json({
      message: "done",
      access_token,
      refresh_token
    });

  } catch (error) {

    res.status(error.cause?.status || 500).json({
      msg: error.message
    });

  }

};


// ================= LOGIN =================
export const login = async (req, res, next) => {

  try {

    const { email, password } = req.body;

    const attemptsKey = `login::attempts::${email}`;
    const blockKey = `login::block::${email}`;

    const blockTtl = await ttl(blockKey);

    if (blockTtl > 0) {
      throw new Error(
        `account is blocked, try again after ${blockTtl} seconds`,
        { cause: { status: 429 } }
      );
    }

    const ExistUser = await findOne({
      model: userModel,
      filter: { email: email },
    });

    if (!ExistUser) {
      throw new Error("email not exist", {
        cause: { status: 404 }
      });
    }

    if (!ExistUser.isConfirmed) {
      throw new Error("please confirm your email first", {
        cause: { status: 401 }
      });
    }

    const passwordCheck = await Compare(
      password,
      ExistUser.password
    );

    if (!passwordCheck) {

      let attempts = Number(
        await getValue(attemptsKey) || 0
      );

      if (attempts === 0) {
        await setValue({
          key: attemptsKey,
          value: 0,
          ttl: 300
        });
      }

      attempts = await incr(attemptsKey);

      if (attempts >= 5) {

        await setValue({
          key: blockKey,
          value: email,
          ttl: 300
        });

        await deleteKey(attemptsKey);

        throw new Error(
          "account blocked for 5 minutes",
          { cause: { status: 429 } }
        );

      }

      throw new Error(
        `password not matched, ${5 - attempts} attempts remaining`,
        { cause: { status: 401 } }
      );

    }

    await deleteKey(attemptsKey);

    if (ExistUser.twoStepVerification) {

      const otp = await generate_otp();

      await setValue({
        key: `twoStep::login::${email}`,
        value: await Hash(otp, SALT),
        ttl: 120
      });

      eventEmitter.emit("confirm_email", async () => {

        await sendemail({
          to: email,
          subject: "Login Verification",
          html: emailTemplate({
            title: "Login Verification",
            subtitle: "Use the code below to complete your login.",
            otp,
            otpExpiry: "This code expires in 2 minutes."
          })
        });

      });

      return res.status(200).json({
        message: "OTP sent to your email, please verify your login",
        twoStepVerification: true
      });

    }

    ExistUser.phone = await Decrypt(ExistUser.phone);

    const tokenId = randomUUID();

    const access_token = jwt.sign(
      {
        id: ExistUser._id,
      },
      KEY_ACCESS,
      {
        expiresIn: 300,
        issuer: "https://localhost:3000",
        jwtid: tokenId,
      },
    );

    const refresh_token = jwt.sign(
      {
        id: ExistUser._id,
      },
      KEY_REFRESH,
      {
        expiresIn: 36000,
        issuer: "https://localhost:3000",
        jwtid: tokenId,
      },
    );

    res.status(200).json({
      tokens: {
        access_token,
        refresh_token
      }
    });

  } catch (error) {

    res.status(error.cause?.status || 500).json({
      msg: error.message
    });

  }

};

// ================= ENABLE TWO STEP VERIFICATION =================

export const enableTwoStepVerification = async (req, res, next) => {

  try {

    const user = req.user;

    if (user.twoStepVerification) {
      throw new Error("two step verification already enabled", {
        cause: { status: 400 }
      });
    }

    const otp = await generate_otp();

    await setValue({
      key: `twoStep::enable::${user.email}`,
      value: await Hash(otp, SALT),
      ttl: 120
    });

    eventEmitter.emit("confirm_email", async () => {

      await sendemail({
        to: user.email,
        subject: "Enable Two Step Verification",
        html: emailTemplate({
          title: "Two Step Verification",
          subtitle: "Use the code below to enable two step verification.",
          otp,
          otpExpiry: "This code expires in 2 minutes."
        })
      });

    });

    res.status(200).json({
      message: "OTP sent to your email"
    });

  } catch (error) {

    res.status(error.cause?.status || 500).json({
      msg: error.message
    });

  }

};
// ================= CONFIRM TWO STEP VERIFICATION =================

export const confirmTwoStepVerification = async (req, res, next) => {

  try {

    const { otp } = req.body;

    const user = req.user;

    const otpValue = await getValue(
      `twoStep::enable::${user.email}`
    );

    if (!otpValue) {
      throw new Error("otp is expired", {
        cause: { status: 400 }
      });
    }

    if (!(await Compare(otp, otpValue))) {
      throw new Error("invalid otp", {
        cause: { status: 400 }
      });
    }

    await findOnedAndUpdate({
      model: userModel,
      filter: {
        _id: user._id
      },
      update: {
        twoStepVerification: true
      }
    });

    await deleteKey(`twoStep::enable::${user.email}`);

    res.status(200).json({
      message: "two step verification enabled successfully"
    });

  } catch (error) {

    res.status(error.cause?.status || 500).json({
      msg: error.message
    });

  }

};
// ================== verifyLoginOtp=======================
export const verifyLoginOtp = async (req, res, next) => {

  try {

    const { email, otp } = req.body;

    const user = await findOne({
      model: userModel,
      filter: { email }
    });

    if (!user) {
      throw new Error("email not exist", {
        cause: { status: 404 }
      });
    }

    if (!user.twoStepVerification) {
      throw new Error("two step verification is not enabled", {
        cause: { status: 400 }
      });
    }

    const otpKey = `twoStep::login::${email}`;

    const otpValue = await getValue(otpKey);

    if (!otpValue) {
      throw new Error("otp is expired", {
        cause: { status: 400 }
      });
    }

    if (!(await Compare(otp, otpValue))) {
      throw new Error("invalid otp", {
        cause: { status: 400 }
      });
    }

    await deleteKey(otpKey);

    const tokenId = randomUUID();

    const access_token = jwt.sign(
      { id: user._id },
      KEY_ACCESS,
      {
        expiresIn: 300,
        issuer: "https://localhost:3000",
        jwtid: tokenId
      }
    );

    const refresh_token = jwt.sign(
      { id: user._id },
      KEY_REFRESH,
      {
        expiresIn: 36000,
        issuer: "https://localhost:3000",
        jwtid: tokenId
      }
    );

    res.status(200).json({
      message: "login successfully",
      tokens: {
        access_token,
        refresh_token
      }
    });

  } catch (error) {

    res.status(error.cause?.status || 500).json({
      msg: error.message
    });

  }

};
// ================= PROFILE =================

export const profile = async (req, res, next) => {

  res.status(200).json({
    user: req.user
  });

};


// ================= REFRESH TOKEN =================

export const refreshToken = async (req, res, next) => {

  const { authorization } = req.headers;

  console.log(req.headers);
  console.log(authorization);

  if (!authorization) {
    throw new Error("token not exist", {
      cause: { status: 404 }
    });
  }

  const decoded = jwt.verify(
    authorization,
    KEY_REFRESH
  );

  if (!decoded?.id) {
    throw new Error("invalid token", {
      cause: { status: 400 }
    });
  }

  const user = await findOne({
    model: userModel,
    filter: {
      _id: decoded.id,
    },
  });

  if (!user) {
    throw new Error("user not exist", {
      cause: { status: 400 }
    });
  }

  const access_token = jwt.sign(
    { id: user._id },
    KEY_ACCESS,
    {
      expiresIn: 300,
    }
  );

  res.status(200).json({
    message: "done",
    access_token
  });

};


// ================= SHARE PROFILE =================

export const shareProfile = async (req, res, next) => {

  const { id } = req.params;

  let user = await findById({
    model: userModel,
    ID: id,
    options: {
      password: 0,
      isConfirmed: 0,
      _id: 0,
      provider: 0,
      createdAt: 0,
      updatedAt: 0,
      __v: 0,
      id: 0,
    },
  });

  if (!user) {
    throw new Error("user not exist", {
      cause: { status: 400 }
    });
  }

  user.phone = await Decrypt(user.phone);

  res.status(200).json({ user });

};


// ================= UPDATE PROFILE =================

export const updateProfile = async (req, res, next) => {

  const {
    fName,
    lName,
    age,
    phone
  } = req.body;

  let updateObj = {};

  if (fName !== undefined) updateObj.fName = fName;

  if (lName !== undefined) updateObj.lName = lName;

  if (age !== undefined) updateObj.age = age;

  if (phone !== undefined) {
    updateObj.phone = await Encrypt(phone);
  }

  let user = await findOnedAndUpdate({
    model: userModel,
    filter: {
      _id: req.user._id,
    },
    update: updateObj,
  });

  user.phone = await Decrypt(user.phone);

  res.status(200).json({
    message: "done on update",
    user
  });

};


// ================= UPDATE PASSWORD =================

export const updatePassword = async (req, res, next) => {

  const {
    oldPassword,
    newPassword
  } = req.body;

  if (!(await Compare(oldPassword, req.user.password))) {
    throw new Error("the old password is wrong", {
      cause: { status: 401 }
    });
  }

  req.user.password = await Hash(newPassword, SALT);

  req.user.changeCredentialAt = new Date();

  await req.user.save();

  res.status(200).json({
    message: "password updated",
    user: req.user
  });

};


// ================= LOGOUT =================

export const logout = async (req, res, next) => {

  const { flag } = req.query;

  if (flag == "all") {

    req.user.changeCredentialAt = Date.now();

    await deleteKey(
      await keys(`revoke_token::${req.user._id}`)
    );

    await req.user.save();

  } else {

    await setValue({
      key: `revoke_token::${req.user._id}::${req.decoded.jti}`,
      value: req.decoded.jti,
      ttl: req.decoded.exp - Math.floor(Date.now() / 1000)
    });

  }

  res.status(200).json({
    message: "done on logout"
  });

};