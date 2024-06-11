const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'hola123.',
    database: 'tenis'
});

db.connect(err => {
    if (err) {
        console.error('Error conectando a la base de datos:', err);
    } else {
        console.log('Conectado a la base de datos.');
    }
});

function validarContraseña(contraseña) {
    const minLength = 8;
    const tieneMayuscula = /[A-Z]/.test(contraseña);
    const tieneMinuscula = /[a-z]/.test(contraseña);
    const tieneEspecial = /[^A-Za-z0-9]/.test(contraseña);
    const tieneLongitudMinima = contraseña.length >= minLength;
    const noTieneNumerosConsecutivos = !/(\d)\1/.test(contraseña);
    const noTieneLetrasConsecutivas = !/(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(contraseña);

    return tieneMayuscula && tieneMinuscula && tieneEspecial && tieneLongitudMinima && noTieneNumerosConsecutivos && noTieneLetrasConsecutivas;
}

app.post('/registro', (req, res) => {
    const { usuario, fecha_nacimiento, email, contraseña } = req.body;

    if (!validarContraseña(contraseña)) {
        return res.status(400).json({ mensaje: 'La contraseña no cumple con los requisitos de seguridad.' });
    }

    const hash = bcrypt.hashSync(contraseña, 10);

    const query = 'INSERT INTO Usuarios (usuario, fecha_nacimiento, email, contraseña) VALUES (?, ?, ?, ?)';
    db.query(query, [usuario, fecha_nacimiento, email, hash], (err, result) => {
        if (err) {
            console.error('Error al registrar usuario:', err);
            return res.status(500).json({ mensaje: 'Error al registrar usuario.' });
        }
        res.status(201).json({ mensaje: 'Usuario registrado exitosamente.' });
    });
});

app.post('/login', (req, res) => {
    const { usuario, contraseña } = req.body;

    const query = 'SELECT * FROM Usuarios WHERE usuario = ?';
    db.query(query, [usuario], (err, results) => {
        if (err) {
            console.error('Error al buscar usuario:', err);
            return res.status(500).json({ mensaje: 'Error al iniciar sesión.' });
        }

        if (results.length === 0) {
            return res.status(401).json({ mensaje: 'Usuario o contraseña incorrectos.' });
        }

        const user = results[0];
        if (bcrypt.compareSync(contraseña, user.contraseña)) {
            const token = jwt.sign({ usuario: user.usuario }, 'claveSecreta', { expiresIn: '1h' });
            res.json({ mensaje: 'Inicio de sesión exitoso', token });
        } else {
            res.status(401).json({ mensaje: 'Usuario o contraseña incorrectos.' });
        }
    });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
