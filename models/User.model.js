const { Schema, model } = require("mongoose");
const bcrypt = require("bcryptjs");
// TODO: Please make sure you edit the user model to whatever makes sense in this case
const userSchema = new Schema({
  username: {
    type: String,
    unique: true,
    required: [true, 'Username is required']
  },
  password: {
    type: String,
    required: [true, 'Password is required']
  }
  
});


userSchema.pre("save", async function(next) {
  const user = this;
  if (!user.isModified("password")) {
  return next();
  }

  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(user.password, salt);
  user.password = hash;

  next();
  });

  const User = model("User", userSchema);

module.exports = User;
