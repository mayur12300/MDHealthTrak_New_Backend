import { OAuth2Client } from 'google-auth-library';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import axios from 'axios';
import * as jwt from 'jsonwebtoken';
import jwkToPem from 'jwk-to-pem';

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export async function verifyGoogleToken(idToken: string) {
  const ticket = await client.verifyIdToken({
    idToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();

  if (!payload) {
    throw new BadRequestException('Invalid Google token');
  }

  if (!payload.email_verified) {
    throw new UnauthorizedException('Google email not verified');
  }

  return payload;
}

export async function verifyFacebookToken(accessToken: string) {
  try {
    const debugRes = await axios.get('https://graph.facebook.com/debug_token', {
      params: {
        input_token: accessToken,
        access_token: `${process.env.FB_APP_ID}|${process.env.FB_APP_SECRET}`,
      },
    });

    const debugData = debugRes.data?.data;

    if (!debugData?.is_valid) {
      throw new BadRequestException('Invalid Facebook token');
    }

    const { data } = await axios.get('https://graph.facebook.com/me', {
      params: {
        access_token: accessToken,
        fields: 'id,name,email,picture.type(large)',
      },
    });

    if (!data?.id) {
      throw new BadRequestException('Invalid Facebook token');
    }

    return {
      id: data.id,
      email: data.email || null, // email can be missing
      name: data.name,
      picture: data.picture?.data?.url || null,
    };
  } catch (err) {
    console.error(
      'Facebook token verification error:',
      err.response?.data || err.message,
    );

    throw new BadRequestException('Invalid or expired Facebook access token');
  }
}

export async function verifyAppleToken(idToken: string) {
  const appleKeys = await axios.get('https://appleid.apple.com/auth/keys');

  const decoded: any = jwt.decode(idToken, { complete: true });
  if (!decoded) throw new Error('Invalid Apple token');

  const key = appleKeys.data.keys.find((k) => k.kid === decoded.header.kid);

  if (!key) throw new Error('Apple public key not found');

  const pem = jwkToPem(key);

  const payload: any = jwt.verify(idToken, pem, {
    algorithms: ['RS256'],
    issuer: 'https://appleid.apple.com',
  });

  return payload;
}
