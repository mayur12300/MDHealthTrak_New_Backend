import {
  IsOptional,
  IsString,
  IsEmail,
  IsNotEmpty,
  IsEnum,
} from 'class-validator';

export class LoginGoogleDto {
  @IsOptional()
  @IsString()
  readonly userId?: string;

  @IsOptional()
  @IsString()
  readonly mobile?: string;

  @IsOptional()
  @IsEmail()
  readonly email?: string;

  @IsString()
  @IsNotEmpty()
  readonly idToken?: string;

  @IsEnum(['patient', 'family', 'doctor'])
  role: 'patient' | 'family' | 'doctor';
}
