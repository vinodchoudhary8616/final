"use strict";
const { Model } = require("sequelize");
module.exports = (sequelize, DataTypes) => {
  class Admin extends Model {
  
    resetPass(password) {
      return this.update({ password });
    }

    static createAdmin({ firstName, lastName, email, password }) {
      return this.create({
        firstName,
        lastName,
        email,
        password,
      });
    }
    static associate(models) {
      Admin.hasMany(models.Election, {
        foreignKey: "adminID",
      });
    }
  }
  Admin.init(
    {
      firstName: DataTypes.STRING,
      lastName: DataTypes.STRING,
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
      },
      role: {
        type: DataTypes.STRING,
        defaultValue: "admin",
      },
      password: DataTypes.STRING,
    },
    {
      sequelize,
      modelName: "Admin",
    }
  );
  return Admin;
};