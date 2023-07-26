import Users from '../models/UserModel.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';

export const getUsers = async (req, res) => {
    try {
        const users = await Users.findAll({
            attributes:['id','name','email']
        });
        res.json(users);
    } catch (e) {
        console.log(e);
    }
};

export const Register = async (req, res) => {
    if (req.body.password !== req.body.confPassword) {
        return res.status(400).json({ msg: 'Password dan Confirm Password Tidak Cocok' });
    }

    const salt = await bcrypt.genSalt();
    const hashPassword = await bcrypt.hash(req.body.password, salt);
    
    const min = 100000;
    const max = 999999;
    const otp = Math.floor(Math.random() * (max - min + 1)) + min;

    const emailOtp = await bcrypt.hash(`${req.body.email} + ${otp}`, salt);
    const hashOtp = await bcrypt.hash(`${otp}`, salt);
    
    const transporter = nodemailer.createTransport({
        host: 'sandbox.smtp.mailtrap.io',
        port: 2525,
        auth: {
            user: '301fdb91d40c5f',
            pass: 'd8ce2f46f6840b',
        },
    });

    try {
        const mailOptions = {
            from: 'fikrihabibramadhan@gmail.com',
            to: req.body.email,
            subject: 'Test OTP Email',
            text: `${otp}`,
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.messageId);
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).send('Error sending email.');
    }

    try {
        await Users.create({
            name: req.body.name,
            email: req.body.email,
            password: hashPassword,
            otp: emailOtp,
            verify:0,
        });

        res.cookie('__otp', hashOtp,{
            httpOnly:true,
            maxAge: 600000,
            // secure: true
        });
        
        res.json({ msg: 'Register berhasil, Kode OTP telah terkirim melalui email anda diberikan waktu 5 menit untuk mengisi otp' });
    } catch (e) {
        console.log(e);
    }
};

export const Login = async (req, res) => {
    try {
        const user = await Users.findAll({
            where:{
                email:req.body.email
            }
        });

        const match = await bcrypt.compare(req.body.password, user[0].password);
        if (!match) {
            return res.status(400).json({msg:'Password tidak cocok'});
        }

        if (user[0].verify == 0) {
            const salt = await bcrypt.genSalt();
            
            const min = 100000;
            const max = 999999;
            const otp = Math.floor(Math.random() * (max - min + 1)) + min;
            
            const hashOtp = await bcrypt.hash(`${otp}`, salt);      
            
            const transporter = nodemailer.createTransport({
                host: 'sandbox.smtp.mailtrap.io',
                port: 2525,
                auth: {
                    user: '301fdb91d40c5f',
                    pass: 'd8ce2f46f6840b',
                },
            });
        
            try {
                const mailOptions = {
                    from: 'fikrihabibramadhan@gmail.com',
                    to: req.body.email,
                    subject: 'Test OTP Email',
                    text: `${otp}`,
                };
        
                const info = await transporter.sendMail(mailOptions);
                console.log('Email sent:', info.messageId);
            } catch (error) {
                console.error('Error sending email:', error);
                res.status(500).send('Error sending email.');
            }
            
            await Users.update(
                {otp:hashOtp},
                {
                    where:{
                        email:req.body.email
                    }
                }
            );

            res.cookie('__otp', hashOtp,{
                httpOnly:true,
                maxAge: 600000,
                // secure: true
            });

            return res.status(401).json({msg:'Akun belum terverifikasi, masukan OTP terlebih dahulu'});
        }

        const userId = user[0].id;
        const name = user[0].name;
        const email = user[0].email;

        const accessToken = jwt.sign({userId, name, email}, process.env.ACCESS_TOKEN_SECRET, {
            expiresIn:'1d'
        });

        const refreshToken = jwt.sign({userId, name, email}, process.env.REFRESH_TOKEN_SECRET, {
            expiresIn:'7d'
        });

        await Users.update({refresh_token:refreshToken},{
            where:{
                id:userId
            }
        });

        res.cookie('refreshToken', refreshToken,{
            httpOnly:true,
            maxAge: 24 * 60 * 60 * 1000,
            // secure: true
        });

        res.json({accessToken});
    } catch (error) {
        res.status(404).json({msg:'email tidak ditemukan'});
    }
}

export const Logout = async (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.sendStatus(204);
    }
    const user = await Users.findAll({
        where: {
            refresh_token: refreshToken,
        },
    });

    if (!user[0]) {
        return res.sendStatus(204);
    }
    const userId = user[0].id;

    await Users.update(
        { refresh_token: null },
        {
            where: {
                id: userId,
            },
        }
    );
    res.clearCookie('refreshToken');
    return res.sendStatus(200);
};

export const otp = async (req, res) => {
    const email = req.body.email;
    const otp = req.body.otp;
    const hashOtp = req.cookies.__otp;

    if (!hashOtp) {
        return res.sendStatus(403).json({msg:'OTP kadaluarsa'});
    }

    const match = await bcrypt.compare(otp, hashOtp);
    if (!match) {
        return res.status(400).json({msg:'OTP salah'});
    }

    const user = await Users.findAll({
        where:{
            email:email
        }
    });
    if (!user) {
        return res.status(404).json({msg:'Akun Tidak Ditemukan'});
    }

    await Users.update(
        { otp:'', verify:1},
        {
            where:{
                email:email
            }
        }
    );
    res.clearCookie('__otp');
    return res.status(200).json({msg:'Akun Terverifikasi'});
}