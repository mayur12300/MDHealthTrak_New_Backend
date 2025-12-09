// src/auth/jwt.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false, // Set to true if you want to ignore token expiration
      secretOrKey: 'yourSecretKey', // Must match the secret in JwtModule.register
    });
  }

  async validate(payload: any) {
    // You can add logic here to fetch user details from the database based on the payload
    // and return a user object that will be attached to the request (req.user)
    return { userId: payload.sub, username: payload.username };
  }
}
