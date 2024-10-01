import express from 'express';
import { register, login, checkAccess } from '../controllers/userController';  // Import the controller functions
import authorize from '../middlewares/userMiddleware';
const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/isauthorized', authorize(),(req, res) => {res.send(req.user());})

export default router;
