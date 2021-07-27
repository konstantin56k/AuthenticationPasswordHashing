const Sequelize = require('sequelize');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { STRING } = Sequelize;
const config = {
  logging: false
};

if(process.env.LOGGING){
  delete config.logging;
}
const conn = new Sequelize(process.env.DATABASE_URL || 'postgres://localhost/acme_pass_db', config);

const User = conn.define('user', {
  username: STRING,
  password: STRING
});

User.byToken = async(token)=> {
  try {
    const user = await User.findByPk(jwt.verify(token, process.env.JWT));
    if(user){
      return user;
    }
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
  catch(ex){
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
};

User.authenticate = async({ username, password })=> {
  
  const user = await User.findOne({
    where: {
      username,
      password
    }
  });
  if(user && await bcrypt.compare(password, user.password)){

    return jwt.sign(user.id, process.env.JWT);
  }
  const error = Error('bad credentials');
  error.status = 401;
  throw error;
};

User.addHook('beforeSave', async function(user) {
  if (user.changed('password')) {
    user.password = await bcrypt.hash(user.password, 10)
  }
})

const syncAndSeed = async()=> {
  await conn.sync({ force: true });

  const credentials = [
    { username: 'lucy', password: 'lucy_pw'},
    { username: 'moe', password: 'moe_pw'},
    { username: 'larry', password: 'larry_pw'}
  ];

  const [lucy, moe, larry] = await Promise.all(
    credentials.map( credential => User.create(credential)
    )
  );
  return {
    users: {
      lucy,
      moe,
      larry
    }
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User
  }
};