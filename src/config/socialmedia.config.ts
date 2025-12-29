import { OAuth2Client } from 'google-auth-library';
import axios from 'axios';

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export async function verifyGoogleToken(idToken: string) {
  const ticket = await client.verifyIdToken({
    idToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  return ticket.getPayload();
}

export async function verifyFacebookToken(accessToken: string) {
  const { data } = await axios.get(
    'https://graph.facebook.com/me',
    {
      params: {
        access_token: accessToken,
        fields: 'id,name,email,picture.type(large)',
      },
    },
  );

  if (!data?.id) {
    throw new Error('Invalid Facebook token');
  }

  return {
    id: data.id,
    email: data.email,
    name: data.name,
    picture: data.picture?.data?.url,
  };
}
