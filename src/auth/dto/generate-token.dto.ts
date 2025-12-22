import { IsEmail, IsOptional, IsString, MinLength, ValidateIf } from 'class-validator';

export class GenerateTokenDto {
  @ValidateIf(o => !o.mobile)
  @IsEmail()
  email?: string;

  @ValidateIf(o => !o.email)
  @IsString()
  mobile?: string;

  @IsOptional()
  @IsString()
  country_code?: string;

  @IsString()
  @MinLength(6)
  password: string;

  @IsOptional()
  @IsString()
  otp?: string;
}
