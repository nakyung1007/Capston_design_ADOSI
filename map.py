import requests
from concurrent.futures import ThreadPoolExecutor

cities = [
        {"name": "서울", "lat": 37.5665, "lon": 126.9780},
        {"name": "파리", "lat": 48.8566, "lon": 2.3522},
        {"name": "뉴욕", "lat": 40.7128, "lon": -74.0060},
        {"name": "리우데자네이루", "lat": -22.9068, "lon": -43.1729},
        {"name": "카이로", "lat": 30.0444, "lon": 31.2357},
        {"name": "시드니", "lat": -33.8688, "lon": 151.2093}
    ]

# 비동기 처리
executor = ThreadPoolExecutor()

# API 호출 비동기 처리 함수
def get_weather(city):
    lat = city['lat']
    lon = city['lon']
    api_key = '9ca3cf87495eab0ae69dd2cf8ee9ff94'
    url = f'https://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={lon}&appid={api_key}&units=metric'
    response = requests.get(url).json()
    if 'weather' in response:
        weather_description = response['weather'][0]['description']
    else:
        weather_description = '날씨 정보 없음'
    temperature = response.get('main', {}).get('temp', '온도 정보 없음')
    city_weather = {
        'name': city['name'],
        'weather': weather_description,
        'temperature': temperature
    }
    return city_weather