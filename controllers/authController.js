const { generateToken } = require("../services/generateToken");
const { sendMail } = require("../services/sendMail");
const { otpMail } = require("../views/otpMail.ejs");
const { tempMail } = require("../views/tempMail.ejs");
const { JWT_SECRET } = require("../config/keys");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { User } = require("../models/user");

const register = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      countryCode,
      dialCode,
      phone,
      dateOfBirth,
      gender,
      password,
      role,
    } = req.body;

    if (!firstName || !lastName || !email || !phone || !password) {
      return res.status(400).json({ 
        message_en: "Missing fields",
        message_ar: "حقول مفقودة"
      });
    }

    // Generate a random username like "userABCDE"
    const username = `user${Math.random()
      .toString(36)
      .substring(2, 7)
      .toUpperCase()}`;

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        message_en: "Invalid email format",
        message_ar: "تنسيق البريد الإلكتروني غير صحيح" 
      });
    }

    // Check if the email already exists in the database
    const emailLower = email.toLowerCase();
    const existingEmail = await User.findOne({ where: { email: emailLower } });
    if (existingEmail) {
      return res.status(400).json({ 
        message_en: "Email is already in use",
        message_ar: "البريد الإلكتروني مستخدم بالفعل" 
      });
    }

    // Validate country code format (2 uppercase letters)
    const countryCodeRegex = /^[A-Z]{2}$/;
    if (!countryCodeRegex.test(countryCode)) {
      return res.status(400).json({
        message_en: "Invalid country code format. It should be 2 uppercase letters.",
        message_ar: "تنسيق رمز البلد غير صحيح. يجب أن يكون حرفين كبيرين.",
      });
    }

    // Validate dial code format (e.g., +1, +91)
    const dialCodeRegex = /^\+\d{1,4}$/; // Allows + followed
    if (!dialCodeRegex.test(dialCode)) {
      return res.status(400).json({
        message_en: "Invalid dial code format. It should start with + followed by 1 to 4 digits.",
        message_ar: "تنسيق رمز الاتصال غير صحيح. يجب أن يبدأ بـ + متبوعًا بـ 1 إلى 4 أرقام.",
      });
    }

    // Validate phone number format (4 to 15 digits, not starting with 0)
    const phoneRegex = /^[1-9]\d{3,14}$/;
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({
        message_en: "Invalid phone number format. It should be 4 to 15 digits and not start with 0",
        message_ar: "تنسيق رقم الهاتف غير صحيح. يجب أن يكون بين 4 إلى 15 رقمًا ولا يبدأ بـ 0",
      });
    }

    // Check if the phone number already exists in the database
    const existingPhone = await User.findOne({ where: { phone } });
    if (existingPhone) {
      return res.status(400).json({ 
        message_en: "Phone number is already in use",
        message_ar: "رقم الهاتف مستخدم بالفعل" 
      });
    }

    // Validate date of birth format (YYYY-MM-DD) if provided
    if (dateOfBirth) {
      const dobRegex = /^\d{4}-\d{2}-\d{2}$/;
      if (!dobRegex.test(dateOfBirth)) {
        return res.status(400).json({ 
          message_en: "Invalid date of birth format. Use YYYY-MM-DD.",
          message_ar: "تنسيق تاريخ الميلاد غير صحيح. استخدم YYYY-MM-DD." 
        });
      }
    }

    // Validate gender if provided
    if (gender && !["male", "female"].includes(gender)) {
      return res.status(400).json({
        message_en: "Invalid gender. Valid options are: male, female.",
        message_ar: "جنس غير صحيح. الخيارات الصالحة هي: ذكر، أنثى.",
      });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP

    // Validate new password strength
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        message_en: "Weak password. Must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character.",
        message_ar: "كلمة المرور الجديدة ضعيفة. يجب أن تحتوي على 8 أحرف على الأقل، وحرف كبير واحد، وحرف صغير واحد، ورقم واحد، وحرف خاص واحد.",
      });
    }

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if the role is valid
    const validRoles = ["user"];
    if (role && !validRoles.includes(role)) {
      return res.status(400).json({ 
      message_en: "Invalid role. Valid roles are: user.",
      message_ar: "دور غير صحيح. الأدوار الصالحة هي: مستخدم." 
      });
    }
    // If role is not provided, default to 'user'
    const userRole = role || "user";

    // Create a new user with inactive status
    const newUser = new User({
      username,
      firstName,
      lastName,
      email: emailLower, // Store email in lowercase
      countryCode,
      dialCode,
      phone,
      dateOfBirth: dateOfBirth || null,
      gender: gender || null,
      password: hashedPassword,
      otp: otp.toString(),
      role: userRole || "user",
      status: "inactive", // Set status as inactive initially
    });

    // Save the user to the database
    await newUser.save();

    // Send the OTP to the user's email
    const html = otpMail(firstName, otp);
    await sendMail(email, "CNC-419 Project Account Verification Code", html);

    return res.status(201).json({
      message_en: "User registered successfully. Please activate your account using the verification code sent to your email",
      message_ar: "تم تسجيل المستخدم بنجاح. يرجى تفعيل حسابك باستخدام رمز التحقق المرسل إلى بريدك الإلكتروني",
    });
  } catch (error) {
    console.error("Error during registration:", error);
    return res.status(500).json({ 
      message_en: "Internal server error",
      message_ar: "خطأ داخلي في الخادم" 
    });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        message_en: "Please fill all required fields",
        message_ar: "يرجى تعبئة جميع الحقول المطلوبة" 
      });
    }

    // Find user by username in the database
    const emailLower = email.toLowerCase();
    const user = await User.findOne({ where: { email: emailLower } });

    if (!user) {
      return res.status(401).json({
        message_en: "Invalid email or password",
        message_ar: "البريد الإلكتروني أو كلمة المرور غير صحيحة",
        reason: "invalid_credentials",
      });
    }

    // Check user status
    if (user.status !== "active") {
      return res.status(403).json({
        message_en: "Account is not activated. Please activate your account first",
        message_ar: "حساب المستخدم غير مفعل. يرجى تفعيل الحساب أولاً",
        reason: "account_inactive",
      });
    }

    // Check if user is banned
    if (user.isBanned) {
      return res.status(403).json({
        message_en: "Your account has been banned. Please contact support for assistance",
        message_ar: "تم حظر حسابك. يرجى التواصل مع الدعم للمساعدة",
        reason: "account_banned",
      });
    }

    // Compare passwords
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ 
        message_en: "Invalid email or password",
        message_ar: "البريد الإلكتروني أو كلمة المرور غير صحيحة" 
      });
    }

    // Passwords match, generate JWT token
    const token = generateToken(user);

    // Exclude sensitive fields from user data
    // Use Sequelize's attributes option to exclude sensitive fields
    const userData = await User.findOne({
      where: { email: emailLower },
      attributes: {
        exclude: ["id", "password", "otp", "tokenVersion", "updatedAt"],
      },
    });

    return res.status(200).json({ 
      message_en: "Login successful",
      message_ar: "تم تسجيل الدخول بنجاح", 
      user: userData, 
      token 
    });
  } catch (error) {
    console.error("Error during login:", error);
    return res.status(500).json({ 
      message_en: "Internal server error",
      message_ar: "خطأ داخلي في الخادم" 
    });
  }
};

const logout = async (req, res) => {
  try {
    if (!req.user || !req.user.sub) {
      return res.status(401).json({ 
        authorized: false, 
        message_en: "Unauthorized",
        message_ar: "غير مصرح به" 
      });
    }

    // Invalidate tokens by incrementing tokenVersion
    await User.increment({ tokenVersion: 1 }, { where: { id: req.user.sub } });

    // Clear cookies
    res.clearCookie("token");

    return res.status(200).json({ 
      message_en: "Logout successful",
      message_ar: "تم تسجيل الخروج بنجاح" 
    });
  } catch (error) {
    console.error("Error during logout:", error);
    return res.status(500).json({ 
      message_en: "Internal server error",
      message_ar: "خطأ داخلي في الخادم" 
    });
  }
};

const check = async (req, res) => {
  try {
    if (!req.user || !req.user.sub) {
      return res.status(401).json({ 
        authorized: false, 
        message_en: "Unauthorized",
        message_ar: "غير مصرح به" 
      });
    }

    // Fetch user data from the database using id as primary key
    const user = await User.findByPk(req.user.sub, {
      attributes: {
        exclude: ["id", "password", "otp", "tokenVersion", "updatedAt"],
      },
    });

    if (!user) {
      return res.status(404).json({ 
        authorized: false, 
        message_en: "User not found",
        message_ar: "المستخدم غير موجود" 
      });
    }

    return res.status(200).json({ authorized: true, user });
  } catch (error) {
    console.error("Error during user check:", error);
    return res.status(500).json({ 
      authorized: false, 
      message_en: "Internal server error",
      message_ar: "خطأ داخلي في الخادم" 
    });
  }
};

const verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Find the user by email
    const emailLower = email.toLowerCase();
    const user = await User.findOne({ where: { email: emailLower } });

    if (!req.user || req.user.uname === user.username) {
      if (!email || !otp) {
        return res.status(400).json({ 
          message_en: "Please fill all required fields",
          message_ar: "يرجى تعبئة جميع الحقول المطلوبة" 
        });
      }

      if (!user) {
        return res.status(404).json({ 
          message_en: "User not found",
          message_ar: "المستخدم غير موجود" 
        });
      }

      // Check if OTP matches
      if (user.otp !== otp) {
        return res.status(400).json({ 
          message_en: "Invalid verification code",
          message_ar: "رمز التحقق غير صحيح" 
        });
      }

      if (user.status === "active") {
        return res.status(400).json({ 
          message_en: "User is already activated",
          message_ar: "المستخدم مفعل بالفعل" 
        });
      }

      // Save the old status for email notification
      const oldStatus = user.status;

      // Update the user's status in the database
      const newOTP = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
      user.otp = newOTP.toString();
      user.status = "active";

      // Save the user with updated status
      await user.save();

      // Send a welcoming email only for newly activated users with role 'user'
      if (user.role === "user" && oldStatus !== "active") {
        const text =
          "Welcome to CNC-419 Project! Your account has been successfully activated. We are happy to have you join our community. Enjoy a unique and exciting experience with us!";
        const firstName = user.firstName;
        const welcomeHtml = tempMail(firstName, text);
        await sendMail(email, "Welcome to CNC-419 Project!", welcomeHtml);
      }

      return res.status(200).json({ 
        message_en: "Verification code verified successfully",
        message_ar: "تم التحقق من رمز التحقق بنجاح" 
      });
    } else {
      return res.status(401).json({ 
        message_en: "Unauthorized",
        message_ar: "غير مصرح به" 
      });
    }
  } catch (error) {
    console.error("Error during OTP verification:", error);
    return res.status(500).json({ 
      message_en: "Internal server error",
      message_ar: "خطأ داخلي في الخادم" 
    });
  }
};

const resendOTP = async (req, res) => {
  try {
    const { email } = req.body;

    // Find the user by email
    const emailLower = email.toLowerCase();
    const user = await User.findOne({ where: { email: emailLower } });

    if (!req.user || req.user.uname === user.username) {
      if (!email) {
        return res.status(400).json({ 
          message_en: "Please enter all required fields",
          message_ar: "يرجى إدخال جميع الحقول المطلوبة" 
        });
      }

      if (!user) {
        return res.status(404).json({ 
          message_en: "User not found",
          message_ar: "المستخدم غير موجود" 
        });
      }

      // Generate new OTP
      const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP

      // Update the user's OTP in the database
      user.otp = otp;

      //Save the user with updated OTP
      await user.save();

      // Send the OTP to the user's email
      const firstName = user.firstName;
      const html = otpMail(firstName, otp);
      await sendMail(email, "CNC-419 Project Account Verification Code", html);

      return res.status(200).json({ 
        message_en: "Verification code sent successfully to your email",
        message_ar: "تم إرسال رمز التحقق بنجاح إلى بريدك الإلكتروني" 
      });
    } else {
      return res.status(401).json({ 
        message_en: "Unauthorized",
        message_ar: "غير مصرح به" 
      });
    }
  } catch (error) {
    console.error("Error during OTP resend:", error);
    return res.status(500).json({ 
      message_en: "Internal server error",
      message_ar: "خطأ داخلي في الخادم" 
    });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { email, newPassword, otp } = req.body;

    // Find the user by email
    const emailLower = email.toLowerCase();
    const user = await User.findOne({ where: { email: emailLower } });

    if (!req.user || req.user.uname === user.username) {
      if (!email || !newPassword || !otp) {
        return res.status(400).json({ 
          message_en: "Please enter all required fields",
          message_ar: "يرجى إدخال جميع الحقول المطلوبة" 
        });
      }

      if (!user) {
        return res.status(404).json({ 
          message_en: "User not found",
          message_ar: "المستخدم غير موجود" 
        });
      }

      // Check if OTP matches
      if (user.otp !== otp) {
        return res.status(400).json({ 
          message_en: "Invalid verification code",
          message_ar: "رمز التحقق غير صحيح" 
        });
      }

      // Check if the old password is the same as the new password
      const passwordMatch = await bcrypt.compare(newPassword, user.password);
      if (passwordMatch) {
        return res.status(400).json({
          message_en: "New password must be different from the current password",
          message_ar: "يجب أن تكون كلمة المرور الجديدة مختلفة عن الحالية",
        });
      }

      // Validate new password strength
      const passwordRegex =
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      if (!passwordRegex.test(newPassword)) {
        return res.status(400).json({
          message_en: "Weak new password. Must contain at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character.",
          message_ar: "كلمة المرور الجديدة ضعيفة. يجب أن تحتوي على 8 أحرف على الأقل، وحرف كبير واحد، وحرف صغير واحد، ورقم واحد، وحرف خاص واحد.",
        });
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update the user's password in the database
      user.password = hashedPassword;
      user.otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP;
      user.status = "active";

      // Save the user with updated password and OTP
      await user.save();

      // Send a confirmation email to the user
      const text =
        "تم تغيير كلمة المرور الخاصة بك بنجاح. إذا لم تقم بهذا الإجراء، يرجى التواصل معنا فوراً.";
      const firstName = user.fullName.split(" ")[0];
      const html = tempMail(firstName, text);
      await sendMail(email, "تم تغيير كلمة مرورك لحساب ستارت هب!", html);

      return res.status(200).json({ 
        message_en: "Password reset successfully",
        message_ar: "تم إعادة تعيين كلمة المرور بنجاح" 
      });
    } else {
      return res.status(401).json({ 
        message_en: "Unauthorized",
        message_ar: "غير مصرح به" 
      });
    }
  } catch (error) {
    console.error("Error during password reset:", error);
    return res.status(500).json({ 
      message_en: "Internal server error",
      message_ar: "خطأ داخلي في الخادم" 
    });
  }
};

module.exports = {
  register,
  login,
  logout,
  check,
  verifyOTP,
  resendOTP,
  resetPassword,
};
