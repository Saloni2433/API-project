const express = require("express");
const upload = require("../middleware/uploadMiddleware");
const {
  loginEmployee,
  getEmployeeProfile,
  updateEmployeeProfile,
  changePassword,
  forgotPassword,

} = require("../controllers/employeeController");
const { verifyToken } = require("../middleware/authMiddleware");
const { authorize } = require("../middleware/roleMiddleware");

const router = express.Router();


router.post("/login", loginEmployee);
router.post("/forgot-password", forgotPassword);



router.use(verifyToken); // All routes below require employee authentication


router.get("/profile", getEmployeeProfile);
router.put("/profile", upload.single("image"), updateEmployeeProfile);
router.put("/change-password", changePassword);


module.exports = router;
