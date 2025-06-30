const cloudinary = require('cloudinary').v2;
const fs = require('fs');
const { promisify } = require('util');
const writeFileAsync = promisify(fs.writeFile);
const unlinkAsync = promisify(fs.unlink);

exports.uploadFile = async (file, folder = 'vchat') => {
  try {
    // Write the buffer to a temporary file
    const tempFilePath = `/tmp/${Date.now()}-${file.originalname}`;
    await writeFileAsync(tempFilePath, file.buffer);

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(tempFilePath, {
      folder,
      resource_type: 'auto'
    });

    // Delete the temporary file
    await unlinkAsync(tempFilePath);

    return {
      url: result.secure_url,
      publicId: result.public_id,
      resourceType: result.resource_type
    };
  } catch (err) {
    console.error('Error uploading file:', err);
    throw err;
  }
};

exports.deleteFile = async (publicId) => {
  try {
    await cloudinary.uploader.destroy(publicId);
  } catch (err) {
    console.error('Error deleting file:', err);
    throw err;
  }
};