import { IsOptional, IsString, IsEmail } from 'class-validator';

export class VerifyOtpDto {
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
  readonly otp?: string;

  @IsOptional()
  @IsString()
  readonly country_code?: string; // e.g., +91, +1, +971
}
