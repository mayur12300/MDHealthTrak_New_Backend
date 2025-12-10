import { IsOptional, IsString, IsEmail } from 'class-validator';

export class ForgotPasswordMobileDto {
  @IsOptional()
  @IsString()
  readonly userId?: string;

  @IsOptional()
  @IsString()
  readonly mobile?: string;

  @IsOptional()
  @IsString()
  country_code?: string;
}
