const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const employeeSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, "Username is required"],
      unique: true,
      trim: true,
      minlength: [3, "Username must be at least 3 characters long"],
      maxlength: [30, "Username cannot exceed 30 characters"],
      match: [
        /^[a-zA-Z0-9_]+$/,
        "Username can only contain letters, numbers, and underscores",
      ],
    },
    image: {
      type: String,
      default: null,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        "Please enter a valid email",
      ],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters"],
      select: false,
    },
    phone: {
      type: String,
      required: [true, "Phone number is required"],
      match: [/^[\+]?[1-9][\d]{0,15}$/, "Please enter a valid phone number"],
    },
    department: {
      type: String,
      required: [true, "Department is required"],
      trim: true,
      maxlength: [30, "Department cannot exceed 30 characters"],
    },
    position: {
      type: String,
      required: [true, "Position is required"],
      trim: true,
      maxlength: [50, "Position cannot exceed 50 characters"],
    },
    employeeId: {
      type: String,
      trim: true,
    },
    role: {
      type: String,
      default: "employee",
      immutable: true,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    lastLogin: {
      type: Date,
      default: null,
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
    createdBy: {
      type: mongoose.Schema.ObjectId,
      refPath: "createdByModel",
      required: [true, "Employee must be created by an Admin or Manager"],
    },
    createdByModel: {
      type: String,
      required: true,
      enum: ["Admin", "Manager"],
    },
    managedBy: {
      type: mongoose.Schema.ObjectId,
      ref: "Manager",
      default: null,
    },
    salary: {
      type: Number,
      min: [0, "Salary cannot be negative"],
      default: 0,
    },
    joiningDate: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

employeeSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  if (typeof this.password !== "string" || !this.password.trim()) return next();

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

employeeSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

employeeSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  if (typeof this.password !== "string" || !this.password.trim()) return next();

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

employeeSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

employeeSchema.methods.getResetPasswordToken = function () {
  const resetToken = require("crypto").randomBytes(20).toString("hex");

  this.resetPasswordToken = require("crypto")
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

employeeSchema.statics.findByEmail = function (email) {
  if (!email || typeof email !== "string") return null;
  return this.findOne({ email: email.toLowerCase() });
};

employeeSchema.statics.findByDepartment = function (department) {
  return this.find({ department: department, isActive: true });
};

employeeSchema.statics.findByEmployeeId = function (employeeId) {
  return this.findOne({ employeeId: employeeId });
};

module.exports = mongoose.model("Employee", employeeSchema);
