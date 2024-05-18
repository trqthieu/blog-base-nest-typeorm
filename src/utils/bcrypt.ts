/* eslint-disable prettier/prettier */
import * as bcrypt from 'bcrypt';
const saltRounds = 10;
export function hashPassword(plain: string) {
  const salt = bcrypt.genSaltSync(saltRounds);
  return bcrypt.hashSync(plain, salt);
}

export function comparePassword(plain: string, hash: string) {
  return bcrypt.compareSync(plain, hash);
}
