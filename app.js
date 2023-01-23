const express = require("express");
const app = express();
const csrf = require("tiny-csrf");
const cookieParser = require("cookie-parser");
const {
  Admin,
  Election,
  Questions,
  Voter,
  
} = require("./models");
const bodyParser = require("body-parser");
const path = require("path");
const bcrypt = require("bcrypt");
const passport = require("passport");
const connectEnsureLogin = require("connect-ensure-login");
const session = require("express-session");
const flash = require("connect-flash");
const LocalStratergy = require("passport-local");

const saltRounds = 10;

app.set("views", path.join(__dirname, "views"));
app.use(flash());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser("Some secret String"));
app.use(csrf("this_should_be_32_character_long", ["POST", "PUT", "DELETE"]));

app.use(
  session({
    secret: "my-super-secret-key-2837428907583420",
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);
app.use((request, response, next) => {
  response.locals.messages = request.flash();
  next();
});
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  "Admin",
  new LocalStratergy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    (username, password, done) => {
      Admin.findOne({ where: { email: username } })
        .then(async (user) => {
          const result = await bcrypt.compare(password, user.password);
          if (result) {
            return done(null, user);
          } else {
            done(null, false, { message: "InCorrect password" });
          }
        })
        .catch((err) => {
          console.log(err);
          return done(null, false, { message: "InCorrect Email-ID" });
        });
    }
  )
);

passport.use(
  "Voter",
  new LocalStratergy(
    {
      usernameField: "voterid",
      passwordField: "password",
      passReqToCallback: true,
    },
    async (request, username, password, done) => {
      const election = await Election.getElectionURL(request.params.urlString);
      Voter.findOne({ where: { voterid: username, electionID: election.id } })
        .then(async (user) => {
          const result = await bcrypt.compare(password, user.password);
          if (result) {
            return done(null, user);
          } else {
            return done(null, false, { message: "InCorrect password" });
          }
        })
        .catch(() => {
          return done(null, false, { message: "InCorrect Voter-ID" });
        });
    }
  )
);





passport.serializeUser((user, done) => {
  done(null, { id: user.id, role: user.role });
});
passport.deserializeUser((id, done) => {
  if (id.role === "admin") {
    Admin.findByPk(id.id)
      .then((user) => {
        done(null, user);
      })
      .catch((error) => {
        done(error, null);
      });
  } else if (id.role === "voter") {
    Voter.findByPk(id.id)
      .then((user) => {
        done(null, user);
      })
      .catch((error) => {
        done(error, null);
      });
  }
});

app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

//landing page
app.get("/", (request, response) => {
  if (request.user) {
    if (request.user.role === "admin") {
      return response.redirect("/elections");
    } else if (request.user.role === "voter") {
      request.logout((err) => {
        if (err) {
          return response.json(err);
        }
        response.redirect("/");
      });
    }
  } else {
    response.render("index", {
      title: "Online-Voting-App",
      csrfToken: request.csrfToken(),
    });
  }
});






app.get(
  "/elections",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.role === "admin") {
      let loggedinuser = request.user.firstName + " " + request.user.lastName;
      try {
        const elections = await Election.getElections(request.user.id);
        if (request.accepts("html")) {
          response.render("elections", {
            title: "Online-Voting-App",
            userName: loggedinuser,
            elections,
          });
        } else {
          return response.json({
            elections,
          });
        }
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    } else if (request.user.role === "voter") {
      return response.redirect("/");
    }
  }
);

app.get("/signup", (request, response) => {
  response.render("signup", {
    title: "Create a new admin account",
    csrfToken: request.csrfToken(),
  });
});

app.post("/admin", async (request, response) => {
  if (!request.body.firstName) {
    request.flash("error", "Please fill your first name");
    return response.redirect("/signup");
  }
  if (!request.body.email) {
    request.flash("error", "Please fill your correct email-ID");
    return response.redirect("/signup");
  }
  if (!request.body.password) {
    request.flash("error", "Please fill  your correct password");
    return response.redirect("/signup");
  }
  if (request.body.password.length < 8) {
    request.flash("error", "Password should be minimum 8 character");
    return response.redirect("/signup");
  }
  const hashedPwd = await bcrypt.hash(request.body.password, saltRounds);
  try {
    const user = await Admin.createAdmin({
      firstName: request.body.firstName,
      lastName: request.body.lastName,
      email: request.body.email,
      password: hashedPwd,
    });
    request.login(user, (err) => {
      if (err) {
        console.log(err);
        response.redirect("/");
      } else {
        response.redirect("/elections");
      }
    });
  } catch (error) {
    request.flash("error", "Email ID is already taken");
    return response.redirect("/signup");
  }
});

app.get("/login", (request, response) => {
  if (request.user) {
    return response.redirect("/elections");
  }
  response.render("login", {
    title: "Login to your account",
    csrfToken: request.csrfToken(),
  });
});

app.get("/e/:urlString/voter", async (request, response) => {
  try {
    if (request.user) {
      return response.redirect(`/e/${request.params.urlString}`);
    }
    const election = await Election.getElectionURL(request.params.urlString);
    if (election.running && !election.ended) {
      return response.render("voter_login", {
        title: "Login in as Voter",
        urlString: request.params.urlString,
        electionID: election.id,
        csrfToken: request.csrfToken(),
      });
    } else {
      request.flash("Election has successfully");
      return response.render("result");
    }
  } catch (error) {
    console.log(error);
    return response.status(422).json(error);
  }
});

app.post(
  "/session",
  passport.authenticate("Admin", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (request, response) => {
    response.redirect("/elections");
  }
);

app.post(
  "/e/:urlString/voter",
  passport.authenticate("Voter", {
    failureFlash: true,
    failureRedirect: "back",
  }),
  async (request, response) => {
    return response.redirect(`/e/${request.params.urlString}`);
  }
);

app.get("/signout", (request, response, next) => {
  request.logout((err) => {
    if (err) {
      return next(err);
    }
    response.redirect("/");
  });
});

app.get(
  "/password-reset",
  connectEnsureLogin.ensureLoggedIn(),
  (request, response) => {
    if (request.user.role === "admin") {
      response.render("password-reset", {
        title: "Reset your password",
        csrfToken: request.csrfToken(),
      });
    } else if (request.user.role === "voter") {
      return response.redirect("/");
    }
  }
);

app.post(
  "/password-reset",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.role === "admin") {
      if (!request.body.old_password) {
        request.flash("error", "Please fill your old password");
        return response.redirect("/password-reset");
      }
      if (!request.body.new_password) {
        request.flash("error", "Please fill a new password");
        return response.redirect("/password-reset");
      }
      if (request.body.new_password.length < 8) {
        request.flash("error", "Password should be minimum 8 character");
        return response.redirect("/password-reset");
      }
      const hashedNewPwd = await bcrypt.hash(
        request.body.new_password,
        saltRounds
      );
      const result = await bcrypt.compare(
        request.body.old_password,
        request.user.password
      );
      if (result) {
        try {
          Admin.findOne({ where: { email: request.user.email } }).then(
            (user) => {
              user.resetPass(hashedNewPwd);
            }
          );
          request.flash("success", "Password changed successfully");
          return response.redirect("/elections");
        } catch (error) {
          console.log(error);
          return response.status(422).json(error);
        }
      } else {
        request.flash("error", "Old password is InCorrect");
        return response.redirect("/password-reset");
      }
    } else if (request.user.role === "voter") {
      return response.redirect("/");
    }
  }
);

app.get(
  "/elections/create",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.role === "admin") {
      return response.render("newNode", {
        title: "Generate a election",
        csrfToken: request.csrfToken(),
      });
    } else if (request.user.role === "voter") {
      return response.redirect("/");
    }
  }
);

app.post(
  "/elections",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.role === "admin") {
      if (request.body.electionName.length < 5) {
        request.flash("error", "Election name length should be minimum 5");
        return response.redirect("/elections/create");
      }
      if (request.body.urlString.length < 3) {
        request.flash("error", "URL String length should be minimum 3");
        return response.redirect("/elections/create");
      }
      if (
        request.body.urlString.includes(" ") ||
        request.body.urlString.includes("\t") ||
        request.body.urlString.includes("\n")
      ) {
        request.flash("error", "URL String without spaces");
        return response.redirect("/elections/create");
      }
      try {
        await Election.addElection({
          electionName: request.body.electionName,
          urlString: request.body.urlString,
          adminID: request.user.id,
        });
        return response.redirect("/elections");
      } catch (error) {
        request.flash("error", "Election URL is already taken");
        return response.redirect("/elections/create");
      }
    } else if (request.user.role === "voter") {
      return response.redirect("/");
    }
  }
);

app.get(
  "/elections/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.role === "admin") {
      try {
        const election = await Election.getElection(request.params.id);
        if (request.user.id !== election.adminID) {
          request.flash("error", "InCorrect election ID");
          return response.redirect("/elections");
        }
        if (election.ended) {
          return response.render("result");
        }
        const numberOfQuestions = await Questions.getNumberOfQuestions(
          request.params.id
        );
        const numberOfVoters = await Voter.getNumberOfVoters(request.params.id);
        return response.render("election_page", {
          id: request.params.id,
          title: election.electionName,
          urlString: election.urlString,
          running: election.running,
          nq: numberOfQuestions,
          nv: numberOfVoters,
          csrfToken: request.csrfToken(),
        });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    } else if (request.user.role === "voter") {
      return response.redirect("/");
    }
  }
);

app.get(
  "/elections/:id/questions",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.role === "admin") {
      try {
        const election = await Election.getElection(request.params.id);
        if (request.user.id !== election.adminID) {
          request.flash("error", "InCorrect election ID");
          return response.redirect("/elections");
        }
        const questions = await Questions.getQuestions(request.params.id);
        if (!election.running && !election.ended) {
          if (request.accepts("html")) {
            return response.render("questions", {
              title: election.electionName,
              id: request.params.id,
              questions: questions,
              csrfToken: request.csrfToken(),
            });
          } else {
            return response.json({
              questions,
            });
          }
        } else {
          if (election.ended) {
            request.flash("error", "You not change when election has ended");
          } else if (election.running) {
            request.flash("error", "You not change while election is running");
          }
          return response.redirect(`/elections/${request.params.id}/`);
        }
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    } else if (request.user.role === "voter") {
      return response.redirect("/");
    }
  }
);

app.get(
  "/elections/:id/questions/create",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.role === "admin") {
      try {
        const election = await Election.getElection(request.params.id);
        if (request.user.id !== election.adminID) {
          request.flash("error", "InCorrect election ID");
          return response.redirect("/elections");
        }
        if (!election.running) {
          return response.render("addquestion", {
            id: request.params.id,
            csrfToken: request.csrfToken(),
          });
        } else {
          if (election.ended) {
            request.flash("error", "You not change when election has ended");
            return response.redirect(`/elections/${request.params.id}/`);
          }
          request.flash("error", "You not change while election is running");
          return response.redirect(`/elections/${request.params.id}/`);
        }
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    } else if (request.user.role === "voter") {
      return response.redirect("/");
    }
  }
);

app.post(
  "/elections/:id/questions/create",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.role === "admin") {
      if (request.body.question.length < 5) {
        request.flash("error", "Question length should be minimum 5");
        return response.redirect(
          `/elections/${request.params.id}/questions/create`
        );
      }

      try {
        const election = await Election.getElection(request.params.id);
        if (request.user.id !== election.adminID) {
          request.flash("error", "InCorrect election ID");
          return response.redirect("/elections");
        }
        if (election.running) {
          request.flash("error", "You not change while election is running");
          return response.redirect(`/elections/${request.params.id}/`);
        }
        if (election.ended) {
          request.flash("error", "You not change when election has ended");
          return response.redirect(`/elections/${request.params.id}/`);
        }
        const question = await Questions.addQuestion({
          question: request.body.question,
          description: request.body.description,
          electionID: request.params.id,
        });
        return response.redirect(
          `/elections/${request.params.id}/questions/${question.id}`
        );
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    } else if (request.user.role === "voter") {
      return response.redirect("/");
    }
  }
);










module.exports = app;