const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');

const app = express();


app.use(express.json());
app.use(cors());

const port = process.env.PORT || 5000;
const db_user = process.env.DB_USER; // mongodb user 
const db_pass = process.env.DB_PASS; // mongodb password
const secret_key = process.env.SECRET_KEY; // mongodb password
const sendGridApiKey = process.env.SENDGRID_API_KEY; // send grid api key

// set send grid api key
sgMail.setApiKey(sendGridApiKey);


// send email function
async function sendMail(toEmail, subject, confirmationCode) {
    await sgMail.send({
        to: toEmail,
        from: '', // Use the email address or domain you verified above
        subject: subject,
        html: `<strong>Confirmation Code ${confirmationCode} </strong>`,
    });
}

//connect mongodb
const uri = `mongodb+srv://${db_user}:${db_pass}@cluster0.cjfgfqu.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true, serverApi: ServerApiVersion.v1 });

const encryptEmailPassword = (email, password) => {
    const lowerCaseEmail = email.toLowerCase();
    const encryptedText = lowerCaseEmail.trim() + password.trim();
    const authKey = crypto.pbkdf2Sync(encryptedText, secret_key, 1000, 64, 'sha512').toString('hex');
    return authKey;
}

const createJWT = (uid) => {
    const token = jwt.sign({ uid }, secret_key, { expiresIn: '24h' });
    return token;
}

const verifyJWT = (req, res, next) => {
    const authorizationToken = req.headers?.authorization;
    const splitToken = authorizationToken.split(' ')[1];
    jwt.verify(splitToken, secret_key, function (err, decoded) {
        if (err) {
            return res.status(403).send({ message: 'unauthorize' });
        } else {
            req.decoded = decoded;
            next();
        }
    });
}

async function run() {
    try {
        // users collection
        const usersCollection = client.db('inventory').collection('users');
        const categoriesCollection = client.db('inventory').collection('categories');
        const productsCollection = client.db('inventory').collection('products');

        // create user 
        app.post('/register', async (req, res) => {

            const user = req.body;
            const query = { email: user?.email };
            const findUser = await usersCollection.findOne(query);
            if (!findUser) {
                // user name
                user.userName = user.name.trim().replaceAll(/ /g, '.');
                // auth key for authentication
                user.authKey = encryptEmailPassword(user?.email, user?.password);
                // delete user password 
                delete user.password;
                const result = await usersCollection.insertOne(user);
                if (result) {
                    const token = createJWT(result?.insertedId);
                    const getUser = await usersCollection.findOne({ _id: ObjectId(result?.insertedId) });
                    const data = { token: token, user: getUser };
                    res.send(data);
                }
            } else {
                res.send({ status: 'bad', message: 'Email already use' });
            }
        });

        // user login
        app.post('/login', async (req, res) => {
            const loginData = req.body;
            const isHaveUser = await usersCollection.findOne({ email: loginData?.email });
            if (isHaveUser) {
                const verifyAuthKey = encryptEmailPassword(loginData.email, loginData?.password);
                if (isHaveUser?.authKey === verifyAuthKey) {
                    const token = createJWT(isHaveUser?._id);
                    res.send({ token, user: isHaveUser });
                } else {
                    res.send({ status: 'bad', message: 'Password is incorrect.' });
                }
            } else {
                res.send({ status: 'bad', message: 'Users Not Found' });
            }
        });

        // send forget password confirmation code
        app.get('/reset-password/:email/:code', async (req, res) => {
            const email = req.params?.email.toLowerCase();
            const code = req.params?.code.toUpperCase();
            const query = { email };
            const result = await usersCollection.findOne(query);
            if (!result) {
                return res.send({ status: 'bad', message: 'User Not Found.' });
            }
            sendMail(email, 'Confirmation Code For Reset Password.', code);
            res.send({ status: 'good' });
        });

        // update password
        app.post('/reset-password/', async (req, res) => {
            const email = req.body?.email.toLowerCase().trim();
            const password = req.body?.password.trim();
            const query = { email };
            const authKey = encryptEmailPassword(email, password);
            const updatedDoc = {
                $set: {
                    authKey: authKey
                }
            }
            const result = await usersCollection.updateOne(query, updatedDoc);
            res.send(result);
        });

        // get user data 
        app.get('/user', verifyJWT, async (req, res) => {
            const authKey = req.headers?.auth_key;
            const decodedUid = req.decoded?.uid;
            const query = { authKey };
            const user = await usersCollection.findOne(query);
            const stringId = user?._id.toString();
            if (stringId === decodedUid) {
                res.send(user);
            } else {
                res.status(403).send({ message: 'unauthorize' });
            }
        });

        // add category
        app.post('/categories', verifyJWT, async (req, res) => {
            const category = req.body;
            const query = { categoryName: category?.categoryName };
            const findCategory = await categoriesCollection.findOne(query);
            console.log(category);
            if (!findCategory) {
                const result = await categoriesCollection.insertOne(category);
                res.send(result);
            } else {
                res.send({ status: 'bad', message: 'Category already exists.', e: findCategory });
            }
        });

        // get all categories
        app.get('/categories', async (req, res) => {
            const query = {};
            const result = await categoriesCollection.find(query).toArray();
            res.send(result);
        });

        //category update
        app.patch('/categories/:id', verifyJWT, async (req, res) => {
            const updatedCategory = req.body;
            const categoryId = req.params.id;
            const updatedQuery = { _id: ObjectId(categoryId) };
            const updatedDoc = {
                $set: updatedCategory
            };
            const result = await categoriesCollection.updateOne(updatedQuery, updatedDoc);
            res.send(result);
        });

        // delete category by id 
        app.delete('/categories/:id', verifyJWT, async (req, res) => {
            const categoryId = req.params.id;
            const productQuery = { categoryId: categoryId };
            const categoryQuery = { _id: ObjectId(categoryId) };
            // delete product under the category
            const deleteProduct = await productsCollection.deleteMany(productQuery);
            // delete category 
            const deleteCategory = await categoriesCollection.deleteOne(categoryQuery);
            res.send(deleteCategory);
        });

        // insert product 
        app.post('/products', verifyJWT, async (req, res) => {
            const product = req.body;
            const result = await productsCollection.insertOne(product);
            res.send(result);
        });

        // get products and filter by category
        app.get('/products/:categoryId', verifyJWT, async (req, res) => {
            const uid = req.headers?.author_id;
            const categoryId = req.params?.categoryId;
            const query = categoryId != '0' ? { authorId: uid, categoryId: categoryId } : { authorId: uid };
            const result = await productsCollection.aggregate([
                { $match: query },
                {
                    $lookup: {
                        let: { categoryObjId: { "$toObjectId": "$categoryId" } },
                        from: 'categories',
                        pipeline: [
                            { $match: { $expr: { $eq: ["$_id", "$$categoryObjId"] } } }
                        ],
                        as: 'category'
                    }
                },
                {
                    $set: {
                        category: { $arrayElemAt: ["$category", 0] }
                    }
                }
            ]).sort({ _id: -1 }).toArray();
            res.send(result);
        });

        // update product by id 
        app.patch('/products/:id', verifyJWT, async (req, res) => {
            const productId = req.params.id;
            const updatedProduct = req.body;
            const updatedQuery = { _id: ObjectId(productId) };
            const updatedDoc = {
                $set: updatedProduct
            };
            const result = await productsCollection.updateOne(updatedQuery, updatedDoc);
            res.send(result);
        });

        // delete product by id 
        app.delete('/products/:id', verifyJWT, async (req, res) => {
            const productId = req.params.id;
            const query = { _id: ObjectId(productId) };
            const result = await productsCollection.deleteOne(query);
            res.send(result);
        });

    } finally {

    }
}

run().catch(err => console.error(err));

app.get('/', (req, res) => {
    res.send('Inventory server is running');
});

app.listen(port);