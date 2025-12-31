import {
  IsOptional,
  IsString,
  IsEmail,
  IsNotEmpty,
  IsEnum,
} from 'class-validator';

export class SignupGoogleDto {
  @IsOptional()
  @IsString()
  readonly userId?: string;

  @IsOptional()
  @IsString()
  readonly mobile?: string;

  @IsOptional()
  @IsEmail()
  readonly email?: string;

  @IsOptional()
  @IsString()
  readonly data?: string;

  @IsString()
  @IsNotEmpty()
  readonly idToken?: string;

  @IsEnum(['patient', 'family', 'doctor'])
  role: 'patient' | 'family' | 'doctor';
}
