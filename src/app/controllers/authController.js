const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const mailer = require('../../modules/mailer');
const authConfig = require('../../config/auth');

const User = require('../models/User');


const router = express.Router();

function generateToken(params = {}){
    return jwt.sign(params, authConfig.secret, {
        expiresIn: 86400,
    });
}

router.post('/register', async (req, res)=>{
    const {email} = req.body;

    try{
        if(await User.findOne({email})){
            return res.status(400).send({error: 'Email já cadastrado.'});
        }
        const user = await User.create(req.body);

        user.password = undefined;

        return res.send({
            user,
            token: generateToken({id: user._id}),
        });
    }catch(err){
        return res.status(400).send({error: 'Falha ao registrar'});
    }
});

router.post('/authenticate', async (req,res)=>{
    const {email, password} = req.body;

    const user = await User.findOne({email}).select('+password');

    if(!user){
        return res.status(400).send({error: "Usuario não encontrado"});
    }
    if(!await bcrypt.compare(password, user.password)){
        return res.status(400).send({error: "Senha inválida"});
    }

    user.password = undefined;

    const token = jwt.sign({id: user._id}, authConfig.secret, {
        expiresIn: 86400,
    });
    return res.send({
        user,
        token: generateToken({id: user._id}),
    });

});

router.post('/forgot_password', async (req,res)=>{
    const {email} = req.body;

    try{
        const user = await User.findOne({email});
        if(!user){
            return res.status(400).send({error: 'Usuário não encontrado.'});
        }
        const token = crypto.randomBytes(20).toString('hex');
        const now = new Date();
        now.setHours(now.getHours()+1);

        await User.findByIdAndUpdate(user.id, {
            '$set': {
                passwordResetToken: token,
                passwordResetExpires: now,
            }
        });

        mailer.sendMail({
            to: email,
            from: 'gustavo@mim.com',
            template: 'auth/forgot_password',
            context: {token},
        }, (err)=>{
            if(err){
                return res.status(400).send({error: 'Não foi possível enviar o email de recuperação.'})
            }
            return res.send();
        });
    }catch (err) {
        console.log(err);
        res.status(400).send({error: 'Não foi possível acessar a pagina, tente novamente.'});
    }
})
module.exports = app => app.use('/auth', router);