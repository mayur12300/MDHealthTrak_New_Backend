// // auth/strategies/facebook.strategy.ts
// import { PassportStrategy } from '@nestjs/passport';
// import { Strategy } from 'passport-facebook';
// import { Injectable } from '@nestjs/common';
// import { ConfigService } from '@nestjs/config';
// import { AuthService } from '../auth.service';

// @Injectable()
// export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
//   constructor(
//     private authService: AuthService,
//     private configService: ConfigService,
//   ) {
//     super({
//       clientID: configService.get('FACEBOOK_APP_ID'),
//       clientSecret: configService.get('FACEBOOK_APP_SECRET'),
//       callbackURL: configService.get('FACEBOOK_CALLBACK_URL'),
//       profileFields: ['id', 'emails', 'name', 'picture.type(large)'],
//       scope: ['email'],
//     });
//   }

//   async validate(
//     accessToken: string,
//     refreshToken: string,
//     profile: any,
//   ) {
//     return this.authService.validateFacebookUser(profile);
//   }
// }
