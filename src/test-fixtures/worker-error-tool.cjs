module.exports = async function workerErrorTool() {
  throw new Error("fixture failure");
};
