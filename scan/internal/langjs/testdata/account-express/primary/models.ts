import { Model, DataTypes } from 'sequelize'
import * as digests from './digests'

class Member extends Model {}

Member.init({
  handle: DataTypes.STRING,
  secret: {
    type: DataTypes.STRING,
    set (plain: string) {
      this.setDataValue('secret', digests.fingerprint(plain))
    }
  },
  pin: {
    type: DataTypes.STRING,
    set (plain: string) {
      this.setDataValue('pin', digests.strong(plain))
    }
  }
}, { sequelize })
