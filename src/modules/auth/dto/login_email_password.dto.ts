import { IsOptional, IsString, IsEmail } from 'class-validator';

export class LoginEmailPasswordDto {
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
}
