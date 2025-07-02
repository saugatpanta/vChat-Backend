const { v4: uuidv4 } = require('uuid');
const redis = require('redis');
const { createClient } = require('redis');

class WebRTCService {
  constructor() {
    this.redisClient = createClient({ url: process.env.REDIS_URL });
    this.redisClient.connect().then(() => console.log('WebRTC Redis connected'));
    this.redisClient.on('error', (err) => console.log('WebRTC Redis error', err));
  }

  async createRoom(userId, type = 'video') {
    const roomId = uuidv4();
    await this.redisClient.hSet(`room:${roomId}`, {
      host: userId,
      type,
      createdAt: Date.now()
    });
    await this.redisClient.expire(`room:${roomId}`, 86400); // 24 hours TTL
    return roomId;
  }

  async joinRoom(roomId, userId) {
    const roomExists = await this.redisClient.exists(`room:${roomId}`);
    if (!roomExists) throw new Error('Room not found');
    
    await this.redisClient.sAdd(`room:${roomId}:participants`, userId);
    return true;
  }

  async leaveRoom(roomId, userId) {
    await this.redisClient.sRem(`room:${roomId}:participants`, userId);
    const participants = await this.redisClient.sMembers(`room:${roomId}:participants`);
    
    if (participants.length === 0) {
      await this.redisClient.del(`room:${roomId}`);
      await this.redisClient.del(`room:${roomId}:participants`);
    }
    
    return true;
  }

  async getRoomInfo(roomId) {
    const room = await this.redisClient.hGetAll(`room:${roomId}`);
    if (!room.host) throw new Error('Room not found');
    
    const participants = await this.redisClient.sMembers(`room:${roomId}:participants`);
    return {
      ...room,
      participants
    };
  }
}

module.exports = new WebRTCService();