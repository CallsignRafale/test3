const _ = require('lodash');
const {
  action,
  errors: {
    UnauthorizedError,
    ForbiddenError,
  },
} = require('swagger-helper');
const { User, OneSignalPlayer } = require('../../schema');
const {
  MSG_CANNOT_CHANGE_PASS_MISSING,
  MSG_CANNOT_DELETE_PASS_MISSING,
  MSG_CANNOT_NO_PASS,
  MSG_CANNOT_FB_PASS,
  MSG_CANNOT_NO_FB,
} = require('../../constants/messages.const');
const FacebookGraphConnector = require('../../connectors/FacebookGraphConnector');

exports.userGet = action(({ profile }, { user: { _id } }) =>
  User.findById(_id)
    .then((user) => {
      if (!user) {
        throw new UnauthorizedError('accessToken is either wrong or expired');
      }

      return user.toJSON(profile);
    })
);

exports.userHasPassword = action(({ profile }, { user: { _id } }) =>
  User.findById(_id)
    .then((user) => {
      if (!user) {
        throw new UnauthorizedError('accessToken is either wrong or expired');
      }

      return { hasPassword: user.toJSON().hasPassword };
    })
);

exports.userCreate = action(({ body }) => {
  const user = new User(body);
  return user.save()
    .then(() => user.toJSON())
  ;
});

exports.userUpdate = action(({ body }, { user: { _id } }) =>
  User.findById(_id)
    .then((user) => {
      if (!user) {
        throw new UnauthorizedError('accessToken is either wrong or expired');
      }

      if (body.email !== undefined) {
        user.email = body.email;
      }

      const ALLOWED_FIELDS = [
        'firstName',
        'lastName',
        'birthDate',
        'age',
        'gender',
        'height',
        'weight',
        'location',
        'photo',
      ];

      for (const key of ALLOWED_FIELDS) {
        _.set(user, `profile.${key}`, _.get(body, `profile.${key}`));
        user.markModified('profile');
      }

      return user.save();
    })
    .then(user => user.toJSON())
);

exports.userChangePassword = action(({ body }, { user: { _id } }) => {
  const { oldPassword, facebookToken, password } = body;

  let getCheckPasswordPromise;
  let updatedUser;
  if (oldPassword) {
    getCheckPasswordPromise = user => Promise.resolve()
      .then(() => {
        if (!user.password) {
          throw new ForbiddenError(MSG_CANNOT_NO_PASS);
        }

        return user.verifyPassword(oldPassword);
      })
      .then((isOldPasswordValid) => {
        if (!isOldPasswordValid) {
          throw new ForbiddenError('Old password is not valid');
        }
      })
    ;
  } else if (facebookToken) {
    getCheckPasswordPromise = user => Promise.resolve()
      .then(() => {
        if (user.password) {
          throw new ForbiddenError(MSG_CANNOT_FB_PASS);
        }

        if (!_.get(user, 'integrations.facebook')) {
          throw new ForbiddenError(MSG_CANNOT_NO_FB);
        }

        const fb = new FacebookGraphConnector(facebookToken);
        return fb.myInfo();
      })
      .then((fbUser) => {
        if (fbUser.id !== _.get(user, 'integrations.facebook')) {
          throw new ForbiddenError('Wrong Facebook user');
        }
      })
    ;
  } else {
    getCheckPasswordPromise = () =>
      Promise.reject(new ForbiddenError(MSG_CANNOT_CHANGE_PASS_MISSING))
    ;
  }

  return User.findById(_id)
    .then((dbUser) => {
      if (!dbUser) {
        throw new UnauthorizedError('accessToken is either wrong or expired');
      }

      updatedUser = dbUser;
      return getCheckPasswordPromise(dbUser);
    })
    .then(() => {
      updatedUser.password = password;
      return updatedUser.save();
    })
    .then(() => updatedUser.toJSON())
  ;
});

exports.userAddOneSignalPlayerId = action(async ({ body: { playerId } }, { user: { _id } }) => {
  const player = await OneSignalPlayer.findOne({ playerId });
  if (player) {
    await player.remove();
  }

  const oneSignalPlayer = new OneSignalPlayer({
    user: _id,
    playerId,
  });

  await oneSignalPlayer.save();

  return {};
});

exports.userDelete = action(({ body }, { user: { _id } }) => {
  const { password, facebookToken } = body;

  if (!password && !facebookToken) {
    throw new ForbiddenError(MSG_CANNOT_DELETE_PASS_MISSING);
  }

  let getCheckPasswordPromise;
  if (password) {
    getCheckPasswordPromise = (user) => {
      if (!user.password) {
        throw new ForbiddenError(MSG_CANNOT_NO_PASS);
      }

      return user.verifyPassword(password)
        .then((isPasswordValid) => {
          if (!isPasswordValid) {
            throw new ForbiddenError('Password is not valid');
          }

          return user;
        })
      ;
    };
  } else if (facebookToken) {
    getCheckPasswordPromise = (user) => {
      if (user.password) {
        throw new ForbiddenError(MSG_CANNOT_FB_PASS);
      }

      if (!_.get(user, 'integrations.facebook')) {
        throw new ForbiddenError(MSG_CANNOT_NO_FB);
      }

      const fb = new FacebookGraphConnector(facebookToken);
      return fb.myInfo()
        .then((fbUser) => {
          if (fbUser.id !== _.get(user, 'integrations.facebook')) {
            throw new ForbiddenError('Wrong Facebook user');
          }

          return user;
        })
      ;
    };
  }

  return User.findById(_id)
    .then((user) => {
      if (!user) {
        throw new UnauthorizedError('accessToken is either wrong or expired');
      }

      return getCheckPasswordPromise(user);
    })
    .then(user => user.remove())
    .then(() => ({}))
  ;
});
