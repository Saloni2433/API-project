const express = require("express");

const upload = require("../middleware/uploadMiddleware");
const {
  registerAdmin,
  loginAdmin,
  getAdminProfile,
  updateAdminProfile,
  changePassword,
  forgotPassword,
  getAllManagers,
  getAllEmployees,

} = require("../controllers/adminController");
const { createManager } = require("../controllers/managerController");
const { verifyToken } = require("../middleware/authMiddleware");
const { adminOnly } = require("../middleware/roleMiddleware");

const router = express.Router();

router.post(
  "/register",
  upload.single("image"),
  registerAdmin
);
router.post("/login", loginAdmin);
router.post("/forgot-password", forgotPassword);


router.use(verifyToken); // All routes below require admin authentication


router.get("/profile", getAdminProfile);
router.put("/profile", upload.single("image"), updateAdminProfile);
router.put("/change-password", changePassword);


router.post("/managers", createManager);
router.get("/managers", getAllManagers);
router.put("/managers/:id/toggle-status", adminOnly, require("../controllers/adminController").toggleManagerStatus);



router.get("/employees", getAllEmployees);
router.put("/employees/:id/toggle-status", adminOnly, require("../controllers/adminController").toggleEmployeeStatus);





router.get('/health', (req, res) => {
  res.json({ success: true, message: 'Admin API is healthy' });
});


router.all('*', (req, res) => {
  res.status(404).json({ success: false, message: 'Admin API endpoint not found' });
});

module.exports = router;
