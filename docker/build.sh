pwd=$(pwd)
echo $pwd
source=$(dirname $0)
echo $source
cd $source
docker build -t innofocus/haprestio:latest .
cd $pwd
