import { Strategy } from 'passport-openidconnect';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { UserService } from 'src/user/user.service';
import * as O from 'fp-ts/Option';
import * as E from 'fp-ts/Either';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class OIDCStrategy extends PassportStrategy(Strategy) {
  constructor(
    private authService: AuthService,
    private usersService: UserService,
    private configService: ConfigService,
  ) {
    super({
      providerName: configService.get('INFRA.OIDC_PROVIDER_NAME'),
      issuer: configService.get('INFRA.OIDC_ISSUER'),
      authorizationURL: configService.get('INFRA.OIDC_AUTH_URL'),
      tokenURL: configService.get('INFRA.OIDC_TOKEN_URL'),
      userInfoURL: configService.get('INFRA.OIDC_USER_INFO_URL'),
      clientID: configService.get('INFRA.OIDC_CLIENT_ID'),
      clientSecret: configService.get('INFRA.OIDC_CLIENT_SECRET'),
      callbackURL: configService.get('INFRA.OIDC_CALLBACK_URL'),
      scope: [configService.get('INFRA.OIDC_SCOPE')],
      store: true,
    });
  }

  async validate(accessToken, refreshToken, profile, done) {
    const user = await this.usersService.findUserByEmail(
      profile.emails[0].value,
    );

    if (O.isNone(user)) {
      const createdUser = await this.usersService.createUserSSO(
        accessToken,
        refreshToken,
        profile,
      );
      return createdUser;
    }

    /**
     * * displayName and photoURL maybe null if user logged-in via magic-link before SSO
     */
    if (!user.value.displayName || !user.value.photoURL) {
      const updatedUser = await this.usersService.updateUserDetails(
        user.value,
        profile,
      );
      if (E.isLeft(updatedUser)) {
        throw new UnauthorizedException(updatedUser.left);
      }
    }

    /**
     * * Check to see if entry is present in the Account table for user
     * * If user was created with another provider findUserByEmail may return true
     */
    const providerAccountExists =
      await this.authService.checkIfProviderAccountExists(user.value, profile);

    if (O.isNone(providerAccountExists))
      await this.usersService.createProviderAccount(
        user.value,
        accessToken,
        refreshToken,
        profile,
      );

    return user.value;
  }
}
