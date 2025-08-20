const express = require("express");

const upload = require("../middleware/uploadMiddleware");
const {
  loginManager,
  getManagerProfile,
  updateManagerProfile,
  changePassword,
  forgotPassword,

  createEmployee,
  getManagedEmployees,
  getEmployeeById,
} = require("../controllers/managerController");
const { verifyToken } = require("../middleware/authMiddleware");
const {
  managerOrAdmin,
  canManageEmployee,
} = require("../middleware/roleMiddleware");

const router = express.Router();





router.post("/login", loginManager);
router.post("/forgot-password", forgotPassword);



router.use(verifyToken); // All routes below require manager authentication


router.get("/profile", getManagerProfile);
router.put("/profile", upload.single("image"), updateManagerProfile);
router.put("/change-password", changePassword);


router.post("/employees", upload.single("image"), createEmployee);
router.get("/employees", getManagedEmployees);
router.get("/employees/:id", canManageEmployee, getEmployeeById);

module.exports = router;
