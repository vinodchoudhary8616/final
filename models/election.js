"use strict";
const { Model, where } = require("sequelize");
module.exports = (sequelize, DataTypes) => {
  class Election extends Model {
    static addElection({ electionName, adminID, urlString }) {
      return this.create({
        electionName,
        urlString,
        adminID,
      });
    }

    
    static launchElection(id) {
      return this.update(
        {
          running: true,
        },
        {
          returning: true,
          where: {
            id,
          },
        }
      );
    }

    static endElection(id) {
      return this.update(
        {
          running: false,
          ended: true,
        },
        {
          returning: true,
          where: {
            id,
          },
        }
      );
    }

    static getElections(adminID) {
      return this.findAll({
        where: {
          adminID,
        },
        order: [["id", "ASC"]],
      });
    }

    static getElection(id) {
      return this.findOne({
        where: {
          id,
        },
      });
    }

    static getElectionURL(urlString) {
      return this.findOne({
        where: {
          urlString,
        },
      });
    }

    static associate(models) {

      Election.belongsTo(models.Admin, {
        foreignKey: "adminID",
      });

      Election.hasMany(models.Questions, {
        foreignKey: "electionID",
      });

      Election.hasMany(models.Voter, {
        foreignKey: "electionID",
      });

      Election.hasMany(models.Answer, {
        foreignKey: "electionID",
      });
    }
  }
  Election.init(
    {
      electionName: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      urlString: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
      },
      running: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
      },
      ended: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
      },
    },
    {
      sequelize,
      modelName: "Election",
    }
  );
  return Election;
};